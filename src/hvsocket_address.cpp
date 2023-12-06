/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "hvsocket_address.hpp"

#if defined(ZMQ_HAVE_HVSOCKET)

#include <ComputeCore.h>
#pragma comment(lib, "ComputeCore")

//
// Windows Registry Editor Version 5.00
//
// [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx]
// "ElementName"="Your Channel Name"
//

#include <climits>
#include <string>
#include <sstream>
#include <iomanip>

#include "err.hpp"

// TinyJson by Rafa García (https://github.com/rafagafe/tiny-json)
//
// Included below is a fork, to be modified to handle
// UTF-16 directly as this is what HCS returns.
//
// https://github.com/axelriet/tiny-json.git
//

#include "..\external\tiny-json\tiny-json.h"
#include "..\external\tiny-json\tiny-json.c"

zmq::hvsocket_address_t::hvsocket_address_t ()
{
    memset (&address, 0, sizeof address);
}

zmq::hvsocket_address_t::hvsocket_address_t (ctx_t *parent_) : parent (parent_)
{
    memset (&address, 0, sizeof address);
}

zmq::hvsocket_address_t::hvsocket_address_t (const sockaddr *sa,
                                             socklen_t sa_len,
                                             ctx_t *parent_) :
    parent (parent_)
{
    zmq_assert (sa && sa_len > 0);

    memset (&address, 0, sizeof (address));

    if (sa->sa_family == parent->get_hvsocket_socket_family ()) {
        zmq_assert (sa_len <= sizeof (address));
        memcpy (&address, sa, sa_len);
    }
}

static bool GuidFromString (_In_z_ const char *str, _Out_ GUID *guid)
{
    //
    // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    //

    *guid = GUID_NULL;

    const size_t len = strlen (str);

    if (len != 36) {
        return false;
    }

    //
    // Validate the string format
    //

    for (int i = 0; i < len; ++i) {
        const char g = str[i];
        if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
            if (g != '-') {
                return false;
            }
        } else if (!std::isxdigit (g)) {
            return false;
        }
    }

    char *pEnd;

    guid->Data1 = strtoul (str, &pEnd, 16);
    guid->Data2 = (unsigned short) strtoul (str + 9, &pEnd, 16);
    guid->Data3 = (unsigned short) strtoul (str + 14, &pEnd, 16);

    char b[3]{};

    b[0] = str[19];
    b[1] = str[20];

    guid->Data4[0] = (unsigned char) strtoul (b, &pEnd, 16);

    b[0] = str[21];
    b[1] = str[22];

    guid->Data4[1] = (unsigned char) strtoul (b, &pEnd, 16);

    for (int i = 0; i < 6; ++i) {
        memcpy (b, str + 24 + i * 2, 2 * sizeof (b[0]));
        guid->Data4[2 + i] = (unsigned char) strtoul (b, &pEnd, 16);
    }

    return true;
}

std::ostream &operator<< (std::ostream &os, REFGUID guid)
{
    os << std::uppercase;

    os << std::hex << std::setfill ('0') << std::setw (8) << guid.Data1 << '-';

    os << std::hex << std::setfill ('0') << std::setw (4) << guid.Data2 << '-';

    os << std::hex << std::setfill ('0') << std::setw (4) << guid.Data3 << '-';

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[0]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[1]) << '-';

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[2]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[3]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[4]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[5]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[6]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[7]);

    os << std::nouppercase;

    return os;
}

static bool ComputeSystemIdFromNameOrIndex (_In_z_ const char *nameOrIndex,
                                            _Out_ GUID *guid)
{
    bool retVal{};
    PWSTR result{};
    json_t buf[64]{};
    HCS_OPERATION op{};

    *guid = GUID_NULL;

    if (!(op = HcsCreateOperation (nullptr, nullptr))) {
        goto cleanup;
    }

    if (FAILED (HcsEnumerateComputeSystems (nullptr, op))) {
        goto cleanup;
    }

    if (FAILED (HcsGetOperationResult (op, &result))) {
        goto cleanup;
    }

    //
    // Optional, but we no longer need the operation past this point
    //

    HcsCloseOperation (op);
    op = nullptr;

    //
    // Json wants UTF-8 :/
    //

    const int resultLen = (int) wcslen (result);
    const int sizeNeeded = WideCharToMultiByte (CP_UTF8, 0, result, resultLen,
                                                nullptr, 0, nullptr, nullptr);

    if (sizeNeeded > 0) {
        std::string jsonText (sizeNeeded, 0);

        if (!WideCharToMultiByte (CP_UTF8, 0, result, resultLen, &jsonText[0],
                                  sizeNeeded, nullptr, nullptr)) {
            goto cleanup;
        }

        //
        // Optional, but we no longer need the UTF-16 text past this point
        //

        LocalFree (result);
        result = nullptr;

        // The Json looks like this (an array of objects)
        //
        // [{
        //     "Id" : "AF5F35E3-FD7A-4573-9449-E47223939979",
        //     "SystemType" : "VirtualMachine",
        //     "Name" : "WinDev2311Eval",
        //     "Owner" : "VMMS",
        //     "RuntimeId" : "af5f35e3-fd7a-4573-9449-e47223939979"
        // }]
        //
        // We only care about "Id" and "Name"
        //

        json_t const *json = json_create (
          const_cast<char *> (jsonText.c_str ()), buf, _countof (buf));

        if (!json) {
            goto cleanup;
        }

        //
        // Minimally validate that we got what we exoected.
        //

        if (json_getType (json) != JSON_ARRAY) {
            goto cleanup;
        }

        unsigned long i{};
        char *end{nullptr};
        bool indexLookup{};
        const char *begin{nameOrIndex};
        const unsigned long index{strtoul (begin, &end, 10)};

        if (end != begin && !*end) {
            //
            // The whole "name" is a number, so it is an index.
            // There is a small risk that someone names their
            // containers/vm with a number, and this will be
            // wrongly interpreted as an index. The alternative
            // is to pollute the connection string syntax and
            // introduce a special notation, like #0 to mean
            // index 0 and not name "0" - not worth it.
            //

            indexLookup = true;
        }

        for (json_t const *entry{json_getChild (json)}; entry != nullptr;
             entry = json_getSibling (entry), i++) {
            //
            // Minimally validate again that we got what we exoected.
            //

            if (json_getType (entry) != JSON_OBJ) {
                goto cleanup;
            }

            //
            // Compare the names, convert the Id to a GUID if there is a match.
            //

            if ((indexLookup && (i == index))
                || !_stricmp (json_getPropertyValue (entry, "Name"),
                              nameOrIndex)) {
                if (!GuidFromString (json_getPropertyValue (entry, "Id"),
                                     guid)) {
                    goto cleanup;
                }

                //
                // Done.
                //

                retVal = true;
                break;
            }
        }
    }

cleanup:

    if (op) {
        HcsCloseOperation (op);
        op = nullptr;
    }

    if (result) {
        LocalFree (result);
        result = nullptr;
    }

    return retVal;
}

static bool ServiceIdFromName (_In_z_ const char *name, _Out_ GUID *guid)
{
    HKEY hKey{};
    bool retVal{};
    DWORD dwIndex{};
    LSTATUS status{};
    char subkeyName[37]{};
    const size_t nameLenght{strlen (name)};
    auto valueName{std::make_unique<char[]> (nameLenght + 1)};

    *guid = GUID_NULL;

    if (!nameLenght || !valueName) {
        //
        // The name cannot be empty.
        //

        goto cleanup;
    }

    status = RegOpenKeyExA (
      HKEY_LOCAL_MACHINE,
      "SOFTWARE\\Microsoft\\Windows "
      "NT\\CurrentVersion\\Virtualization\\GuestCommunicationServices",
      0, KEY_READ, &hKey);

    if (status != ERROR_SUCCESS) {
        //
        // Maybe there is no Hyper-V on this machine.
        //

        goto cleanup;
    }

    //
    // Loop until the end. The buffer exactly accomodates a
    // GUID in string format without the braces, which is
    // the format used there, so we ignore ERROR_MORE_DATA.
    //

    while ((status =
              RegEnumKeyA (hKey, dwIndex++, subkeyName, _countof (subkeyName)))
           != ERROR_NO_MORE_ITEMS) {
        if (status != ERROR_SUCCESS) {
            //
            // We skip the keys that are too long.
            //

            zmq_assert (status == ERROR_MORE_DATA);
            continue;
        }

        DWORD valueNameSize{static_cast<DWORD> (nameLenght + 1)};
        status = RegGetValueA (hKey, subkeyName, "ElementName", RRF_RT_REG_SZ,
                               nullptr, valueName.get (), &valueNameSize);

        if (status != ERROR_SUCCESS) {
            //
            // If the value is too large or missing, or not a string,
            // we skip the key. In particular we don't needlessly
            // string-compare values that are too long.
            //

            zmq_assert ((status == ERROR_MORE_DATA)
                        || (status == ERROR_FILE_NOT_FOUND)
                        || (status == ERROR_UNSUPPORTED_TYPE));
            continue;
        }

        if (_stricmp (valueName.get (), name) == 0) {
            //
            // The key name is the service id.
            //

            if (!GuidFromString (subkeyName, guid)) {
                goto cleanup;
            }

            //
            // Done.
            //

            retVal = true;
            break;
        }
    }

cleanup:

    if (hKey) {
        RegCloseKey (hKey);
        hKey = nullptr;
    }

    return retVal;
}

int zmq::hvsocket_address_t::resolve (const char *path_)
{
#ifndef NDEBUG
    // TODO: Move this into a test?
    GUID guid{};
    zmq_assert (GuidFromString ("C0B6B7FC-0D90-4812-A606-9E8E13709825", &guid));
    std::stringstream s;
    s << guid;
    zmq_assert (s.str () == "C0B6B7FC-0D90-4812-A606-9E8E13709825");
#endif

    //
    // Find the ':' at end that separates the VM ID from the Service ID.
    //

    const char *delimiter = strrchr (path_, ':');

    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }

    //
    // Separate the VM ID / Service ID.
    //

    std::string addr_str (path_, delimiter - path_);
    std::string port_str (delimiter + 1);

    address.VmId = HV_GUID_WILDCARD;
    address.ServiceId = HV_GUID_WILDCARD;

    if (!addr_str.length ()) {
        //
        // Address cannot be empty.
        //

        errno = EINVAL;
        return -1;
    } else if (addr_str != "*") {
        //
        // Try guid conversion first
        //

        if (!GuidFromString (addr_str.c_str (), &address.VmId)) {
            //
            // GuidFromString failed. Check for well-known aliases.
            //

            if (addr_str == "broadcast") {
                address.VmId = HV_GUID_BROADCAST;
            } else if (addr_str == "children") {
                address.VmId = HV_GUID_CHILDREN;
            } else if (addr_str == "loopback") {
                address.VmId = HV_GUID_LOOPBACK;
            } else if (addr_str == "parent") {
                address.VmId = HV_GUID_PARENT;
            } else if (addr_str == "silohost") {
                address.VmId = HV_GUID_SILOHOST;
            } else {
                //
                // Try resolving the string as a VM/Container name or index.
                //

                if (!ComputeSystemIdFromNameOrIndex (addr_str.c_str (),
                                                     &address.VmId)) {
                    //
                    // ComputeSystemIdFromNameOrIndex failed. This was our last hope :(
                    //

                    errno = EINVAL;
                    return -1;
                }
            }
        }
    }

    if (!port_str.length ()) {
        //
        // Port cannot be empty.
        //

        errno = EINVAL;
        return -1;

    } else if (port_str != "*") {
        //
        // Try guid conversion first
        //

        if (!GuidFromString (port_str.c_str (), &address.ServiceId)) {
            //
            // GuidFromString failed. See if it is a numeric port.
            //

            char *end{nullptr};
            const char *begin{port_str.c_str ()};
            const unsigned long portNumber{strtoul (begin, &end, 10)};

            if (end != begin && !*end) {
                //
                // The whole "serviceId" is a number, so it is port number.
                // There is a small risk that someone names their
                // service id's with numbera, and this will be
                // wrongly interpreted as port. The alternative
                // is to pollute the connection string syntax and
                // introduce a special notation, like #5555 to mean
                // port 5555 and not service name "5555" - not worth it.
                //

                if (portNumber & 0x80000000) {
                    //
                    // Port numbers must be <= 0x7fffffff
                    //
                    errno = EINVAL;
                    return -1;
                }

                //
                // It looks like a number that can be used as port number,
                // stuff it into the VSOCK template. This franken-GUID is
                // given special treatment by the underlying transport.
                //

                address.ServiceId = HV_GUID_VSOCK_TEMPLATE;
                address.ServiceId.Data1 = portNumber;
            } else {
                //
                // Try resolving the string as a registered service name.
                //

                if (!ServiceIdFromName (port_str.c_str (),
                                        &address.ServiceId)) {
                    //
                    // ServiceIdFromName failed. This was our last hope :(
                    //

                    errno = EINVAL;
                    return -1;
                }
            }
        }
    }

    address.Family =
      static_cast<unsigned short> (parent->get_hvsocket_socket_family ());

    return 0;
}

int zmq::hvsocket_address_t::to_string (std::string &addr_) const
{
    if (address.Family != parent->get_hvsocket_socket_family ()) {
        addr_.clear ();
        return -1;
    }

    std::stringstream s;

    s << protocol_name::hvsocket << "://";
    s << address.VmId;
    s << ":";
    s << address.ServiceId;

    addr_ = s.str ();

    return 0;
}

const sockaddr *zmq::hvsocket_address_t::addr () const
{
    return reinterpret_cast<const sockaddr *> (&address);
}

socklen_t zmq::hvsocket_address_t::addrlen () const
{
    return static_cast<socklen_t> (sizeof address);
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::hvsocket_address_t::family () const
#else
sa_family_t zmq::hvsocket_address_t::family () const
#endif
{
    return AF_HYPERV;
}

#endif
