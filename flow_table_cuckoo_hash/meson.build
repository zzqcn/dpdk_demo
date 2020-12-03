project('l2fwd', 'c')

if get_option('buildtype').startswith('debug')
    add_project_arguments('-DDEBUG', language: 'c')
endif
add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')

dpdk_dep = declare_dependency(
    dependencies: dependency('libdpdk'),
    link_args: [
        '-Wl,--no-as-needed',
        '-L/usr/local/lib64',
        '-lrte_net_vmxnet3',
        '-lrte_net_ixgbe',
        '-lrte_net_i40e',
        '-lrte_mempool_ring',
    ],
)
#dpdk_dep = dependency('libdpdk', static: true)

sources = files(
    'main.c'
)

executable('l2fwd',sources,
    dependencies: dpdk_dep
)
