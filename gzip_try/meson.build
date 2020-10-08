project('simpletun', 'cpp', 'c',
        license : ['Boost'],
        version : '0.1',
        default_options : ['cpp_std=c++2a', 'warning_level=3', 'werror=false'])

add_project_arguments('-lxc++', language: 'c')

thread_dep = [dependency('threads'), dependency('zlib')]

inc_dir = include_directories(['gzip'])


src = ['src/main.cpp']

executable('simpletun',
            sources : src,
            include_directories : inc_dir,
            dependencies : thread_dep
           )