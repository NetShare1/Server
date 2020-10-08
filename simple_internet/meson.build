project('simpletun', 'cpp', 'c',
        license : ['Boost'],
        version : '0.1',
        default_options : ['cpp_std=c++2a', 'warning_level=3', 'werror=false'])

add_project_arguments('-lxc++', language: 'c')

thread_dep = [dependency('threads')]

inc_dir = include_directories(['brotli', 'brotli/common', 'brotli/enc', 'brotli/dec', 'brotli/include'])


src = ['src/main.cpp',
       'brotli/common/constants.c', 
       'brotli/common/context.c', 
       'brotli/common/dictionary.c', 
       'brotli/common/platform.c', 
       'brotli/common/transform.c', 
       'brotli/dec/bit_reader.c', 
       'brotli/dec/decode.c', 
       'brotli/dec/huffman.c', 
       'brotli/dec/state.c', 
       'brotli/enc/backward_references.c', 
       'brotli/enc/backward_references_hq.c', 
       'brotli/enc/bit_cost.c', 
       'brotli/enc/block_splitter.c', 
       'brotli/enc/brotli_bit_stream.c', 
       'brotli/enc/cluster.c', 
       'brotli/enc/command.c', 
       'brotli/enc/compress_fragment.c', 
       'brotli/enc/compress_fragment_two_pass.c', 
       'brotli/enc/dictionary_hash.c', 
       'brotli/enc/encode.c', 
       'brotli/enc/encoder_dict.c', 
       'brotli/enc/entropy_encode.c', 
       'brotli/enc/fast_log.c', 
       'brotli/enc/histogram.c', 
       'brotli/enc/literal_cost.c', 
       'brotli/enc/memory.c', 
       'brotli/enc/metablock.c', 
       'brotli/enc/static_dict.c', 
       'brotli/enc/utf8_util.c'
       ]

executable('simpletun',
            sources : src,
            include_directories : inc_dir,
            dependencies : thread_dep
           )