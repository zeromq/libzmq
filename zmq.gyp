{
  'target_defaults': {
    'include_dirs': [
      'include',
      'builds/gyp'
    ],
    'defines': [
      '_REENTRANT',
      '_THREAD_SAFE',
      'ZMQ_CUSTOM_PLATFORM_HPP',
      'ZMQ_GYP_BUILD'
    ],
    'conditions': [
      [ 'OS=="win"', {
        'defines': [
          'ZMQ_HAVE_WINDOWS',
          'ZMQ_STATIC',
          'FD_SETSIZE=16384',
          '_CRT_SECURE_NO_WARNINGS',
          '_WINSOCK_DEPRECATED_NO_WARNINGS'
        ],
        'libraries': [
          'ws2_32',
          'advapi32',
          'iphlpapi'
        ]
      }],
      [ 'OS=="mac"', {
        'defines': [
          'ZMQ_HAVE_OSX'
        ],
        'xcode_settings': {
          'GCC_ENABLE_CPP_RTTI': 'YES'
        }
      }],
      [ 'OS=="linux"', {
        'defines': [
          'ZMQ_HAVE_LINUX'
        ],
        'cflags_cc!': [
          '-fno-rtti'
        ],
        'libraries': [
          '-lpthread'
        ]
      }]
    ],
  },
  'default_configuration': 'Debug',
  'configurations': {
    'Debug': {
      'defines': [ 'DEBUG', '_DEBUG' ],
      'cflags': [ '-Wall', '-Wextra', '-O0', '-g', '-ftrapv' ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'RuntimeLibrary': 1, # static debug
        },
      },
    },
    'Release': {
      'defines': [ 'NDEBUG' ],
      'cflags': [ '-Wall', '-Wextra', '-O3' ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'RuntimeLibrary': 0, # static release
        },
      },
    }
  },
  'targets': [
    {
      'target_name': 'libzmq',
      'type': '<(library)',
      'includes': [ 'zmq.gypi' ],
      'sources': [ '<@(zmqsources)' ],
      'copies': [{
        'destination': 'src',
        'files': [ 'builds/gyp/platform.hpp' ]
      }]
    }
  ]
}
