project('filter', 'c')

if get_option('buildtype').startswith('debug')
    add_project_arguments('-DDEBUG', language: 'c')
endif
add_project_arguments(
    '-Werror',
    '-Wfatal-errors',
    '-Wno-unused-function',
    '-Wno-unused-result',
    '-DALLOW_EXPERIMENTAL_API',
    language: 'c',
)

dpdk_dep = declare_dependency(
    dependencies: dependency('libdpdk'),
    #   link_args: [
    #      '-Wl,--no-as-needed',
    #      '-L/usr/local/lib/x86_64-linux-gnu/dpdk/pmds-22.0',
    #      '-lrte_bus_pci',
    #     '-lrte_net_vmxnet3',
    #     '-lrte_net_ixgbe',
    #     '-lrte_net_i40e',
    #     '-lrte_mempool_ring',
    # ],
)
allow_experimental_apis = true

sources = files(
    'decode.c',
    'filter.c',
    'main.c',
)

executable('filter',sources,
    dependencies: dpdk_dep
)
