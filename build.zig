//! Requires zig version: 0.11 or higher
/// build: zig build -Doptimize=ReleaseFast -Dshared (or -Dshared=true/false)
const std = @import("std");
const Builder = std.Build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Options - static library [default]
    const shared = b.option(bool, "shared", "Build the Shared Library [default: false]") orelse false;

    // Generating "platform.hpp"
    const config_header = switch (target.getOsTag()) {
        .linux => b.addConfigHeader(.{
            .style = .blank, //.{ .cmake = .{ .path = "builds/cmake/platform.hpp.in" } },
            .include_path = "platform.hpp",
        }, .{
            .ZMQ_HAVE_LINUX = {},
            .ZMQ_USE_EPOLL = 1,
            .ZMQ_HAVE_CURVE = 1,
            .ZMQ_USE_TWEETNACL = 1,
            .ZMQ_HAVE_EVENTFD = 1,
            .ZMQ_HAVE_IFADDRS = 1,
            .ZMQ_HAVE_SOCK_CLOEXEC = 1,
            .ZMQ_HAVE_SO_BINDTODEVICE = 1,
            .ZMQ_HAVE_SO_KEEPALIVED = 1,
            .ZMQ_HAVE_SO_PEERCRED = 1,
            .ZMQ_HAVE_TCP_KEEPCNT = 1,
            .ZMQ_HAVE_TCP_KEEPIDLE = 1,
            .ZMQ_HAVE_TCP_KEEPINTVL = 1,
            .ZMQ_HAVE_UIO = 1,
            .ZMQ_HAVE_STRLCPY = 1,
            .ZMQ_USE_BUILTIN_SHA1 = 1,
            .HAVE_FORK = 1,
            .HAVE_POSIX_MEMALIGN = 1,
            .HAVE_ACCEPT4 = 1,
            .HAVE_STRNLEN = 1,
            .ZMQ_IOTHREAD_POLLER_USE_EPOLL = 1,
            .ZMQ_USE_CV_IMPL_STL11 = 1,
            .ZMQ_POLL_BASED_ON_POLL = 1,
            .ZMQ_CACHELINE_SIZE = 64,
        }),
        .windows => b.addConfigHeader(.{
            .style = .blank,
            .include_path = "platform.hpp",
        }, .{
            .ZMQ_HAVE_WINDOWS = {},
            .ZMQ_HAVE_MINGW32 = {},
            .ZMQ_HAVE_CURVE = 1,
            .ZMQ_USE_TWEETNACL = 1,
            .ZMQ_USE_SELECT = 1,
            .ZMQ_USE_CV_IMPL_STL11 = 1,
            .ZMQ_CACHELINE_SIZE = 64,
            .ZMQ_IOTHREAD_POLLER_USE_SELECT = 1,
            .ZMQ_POLL_BASED_ON_SELECT = 1,
            .ZMQ_USE_BUILTIN_SHA1 = 1,
            .HAVE_STRNLEN = 1,
        }),
        .macos => b.addConfigHeader(.{
            .style = .blank,
            .include_path = "platform.hpp",
        }, .{
            .ZMQ_HAVE_OSX = {},
            .ZMQ_USE_KQUEUE = 1,
            .ZMQ_POSIX_MEMALIGN = 1,
            .ZMQ_CACHELINE_SIZE = 64,
            .ZMQ_HAVE_CURVE = 1,
            .ZMQ_USE_TWEETNACL = 1,
            .ZMQ_HAVE_UIO = 1,
            .ZMQ_HAVE_IFADDRS = 1,
            .ZMQ_HAVE_OS_KEEPALIVE = 1,
            .ZMQ_HAVE_TCP_KEEPALIVE = 1,
            .ZMQ_HAVE_TCP_KEEPCNT = 1,
            .ZMQ_HAVE_TCP_KEEPINTVL = 1,
            .ZMQ_USE_BUILTIN_SHA1 = 1,
            .ZMQ_IOTHREAD_POLLER_USE_KQEUE = 1,
            .ZMQ_USE_CV_IMPL_STL11 = 1,
            .HAVE_STRNLEN = 1,
            .HAVE_FORK = 1,
        }),
        else => b.addConfigHeader(.{}, .{}),
    };

    const libzmq = if (!shared) b.addStaticLibrary(.{
        .name = "zmq",
        .target = target,
        .optimize = optimize,
    }) else b.addSharedLibrary(.{
        .name = "zmq",
        .target = target,
        .version = .{
            .major = 4,
            .minor = 3,
            .patch = 5,
        },
        .optimize = optimize,
    });
    if (optimize == .Debug or optimize == .ReleaseSafe)
        libzmq.bundle_compiler_rt = true
    else if (shared) libzmq.want_lto = true;
    libzmq.addConfigHeader(config_header);
    libzmq.addIncludePath("include");
    libzmq.addIncludePath("src");
    libzmq.addIncludePath("external");
    libzmq.addIncludePath(config_header.include_path);
    libzmq.addCSourceFiles(cxxSources, cxxFlags);
    libzmq.addCSourceFiles(extraCsources, cFlags);
    if (target.isWindows()) {
        libzmq.addCSourceFile("external/wepoll/wepoll.c", cFlags);
        libzmq.linkSystemLibraryName("ws2_32");
        libzmq.linkSystemLibraryName("rpcrt4");
        libzmq.linkSystemLibraryName("iphlpapi");
        //libzmq.linkSystemLibraryName("rt");
    }
    libzmq.linkLibCpp(); // LLVM libc++ (builtin)
    libzmq.linkLibC(); // OS libc
    libzmq.install();
    libzmq.installHeadersDirectory("include", "");
}

const cFlags: []const []const u8 = &.{
    "-Oz",
    "-Wall",
    "-pedantic",
};
const cxxFlags = cFlags ++ [_][]const u8{"-std=c++14"};
const cxxSources: []const []const u8 = &.{
    "src/kqueue.cpp",
    "src/lb.cpp",
    "src/mailbox.cpp",
    "src/mailbox_safe.cpp",
    "src/mechanism.cpp",
    "src/mechanism_base.cpp",
    "src/metadata.cpp",
    "src/msg.cpp",
    "src/mtrie.cpp",
    "src/norm_engine.cpp",
    "src/object.cpp",
    "src/options.cpp",
    "src/own.cpp",
    "src/null_mechanism.cpp",
    "src/pair.cpp",
    "src/peer.cpp",
    "src/pgm_receiver.cpp",
    "src/pgm_sender.cpp",
    "src/pgm_socket.cpp",
    "src/pipe.cpp",
    "src/plain_client.cpp",
    "src/plain_server.cpp",
    "src/poll.cpp",
    "src/poller_base.cpp",
    "src/polling_util.cpp",
    "src/pollset.cpp",
    "src/proxy.cpp",
    "src/pub.cpp",
    "src/pull.cpp",
    "src/push.cpp",
    "src/random.cpp",
    "src/raw_encoder.cpp",
    "src/raw_decoder.cpp",
    "src/raw_engine.cpp",
    "src/reaper.cpp",
    "src/rep.cpp",
    "src/req.cpp",
    "src/router.cpp",
    "src/select.cpp",
    "src/server.cpp",
    "src/session_base.cpp",
    "src/signaler.cpp",
    "src/socket_base.cpp",
    "src/socks.cpp",
    "src/socks_connecter.cpp",
    "src/stream.cpp",
    "src/stream_engine_base.cpp",
    "src/sub.cpp",
    "src/tcp.cpp",
    "src/tcp_address.cpp",
    "src/tcp_connecter.cpp",
    "src/tcp_listener.cpp",
    "src/thread.cpp",
    "src/trie.cpp",
    "src/radix_tree.cpp",
    "src/v1_decoder.cpp",
    "src/v1_encoder.cpp",
    "src/v2_decoder.cpp",
    "src/v2_encoder.cpp",
    "src/v3_1_encoder.cpp",
    "src/xpub.cpp",
    "src/xsub.cpp",
    "src/zmq.cpp",
    "src/zmq_utils.cpp",
    "src/decoder_allocators.cpp",
    "src/socket_poller.cpp",
    "src/timers.cpp",
    "src/radio.cpp",
    "src/dish.cpp",
    "src/udp_engine.cpp",
    "src/udp_address.cpp",
    "src/scatter.cpp",
    "src/gather.cpp",
    "src/ip_resolver.cpp",
    "src/zap_client.cpp",
    "src/zmtp_engine.cpp",
};
const extraCsources: []const []const u8 = &.{
    "src/tweetnacl.c",
    "external/sha1/sha1.c",
};
