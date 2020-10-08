project('simpletun', 'cpp', 'c',
        license : ['Boost'],
        version : '0.1',
        default_options : ['cpp_std=c++2a', 'warning_level=3', 'werror=false'])

add_project_arguments('-lxc++', language: 'c')

thread_dep = [dependency('threads')]

inc_dir = include_directories(['gipfeli'])


src = ['src/main.cpp',
       'gipfeli/decompress.cc',
       'gipfeli/entropy.cc',
       'gipfeli/entropy_code_builder.cc', 
       'gipfeli/gipfeli-internal.cc',
       'gipfeli/lz77.cc'
       ]

executable('simpletun',
            sources : src,
            include_directories : inc_dir,
            dependencies : thread_dep
           )