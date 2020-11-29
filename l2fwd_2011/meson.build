project('l2fwd', 'c')

if get_option('buildtype').startswith('debug')
    add_project_arguments('-DDEBUG', language: 'c')
endif
add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')

dpdk_dep = dependency('libdpdk')

sources = files(
    'main.c'
)

executable('l2fwd', sources, dependencies: dpdk_dep)