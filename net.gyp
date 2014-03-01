{
  'targets': [
    {
      'target_name': 'net',
      'type': '<(library)',
      'sources': [
        'src/net.c',
        'src/tls.c',
      ],
      'include_dirs': [
        '.',
        'include',
        'deps',
        'deps/buffer',
        'deps/libuv',
      ],
      'dependencies': [
        'deps/libuv/uv.gyp:libuv',
      ],
      'cflags': [
        '-std=c99',
        '-Wall',
      ],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'GCC_C_LANGUAGE_STANDARD': 'c99'
          }
        }]
      ]
    },

    {
      'target_name': 'run-tests',
      'type': 'executable',
      'sources': [
        'tests/simple.c',
      ],
      'include_dirs': [
        '.',
        'include',
        'deps',
        'deps/buffer',
        'deps/libuv',
      ],
      'dependencies': [
        'net',
      ],
      'cflags': [
        '-std=c99',
        '-Wall',
      ],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'GCC_C_LANGUAGE_STANDARD': 'c99'
          }
        }]
      ]
    },

  ]
}

