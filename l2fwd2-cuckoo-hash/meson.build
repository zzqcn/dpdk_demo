project('l2fwd_cuckoo_hash', 'c')

if get_option('buildtype').startswith('debug')
    add_project_arguments('-DDEBUG', language: 'c')
endif
add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')

dpdk_dep = dependency('libdpdk')

sources = files(
    'main.c'
)

executable('l2fwd_cuckoo_hash', sources, dependencies: dpdk_dep)