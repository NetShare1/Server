project('NetShareServer', 'cpp', 'c',
        license : ['Boost'],
        version : '0.1',
        default_options : ['cpp_std=c++2a', 'warning_level=3', 'werror=false'])

add_project_arguments('-lxc++', language: 'c')

thread_dep = [dependency('threads')]


inc_dir = include_directories(['include'])


src = ['src/main.cpp']

executable('netshare',
            sources : src,
            include_directories : inc_dir,
            dependencies : thread_dep
           )