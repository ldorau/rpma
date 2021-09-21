{% if menu is true %}
<a class="pure-menu-heading" href="#dram">DRAM</a>
<ul class="pure-menu-list">
    <li class="pure-menu-item"><a href="#dram-read-bw" class="pure-menu-link">Read</a></li>
    <li class="pure-menu-item"><a href="#dram-write-bw" class="pure-menu-link">Write</a></li>
</ul>
{% else %}

<h2 id="dram" class="page-break">DRAM</h2>

Benchmarking accessing DRAM in two configurations:

- `PCIe Allocating Write Flows = Allocating` along with xADR covering CPU caches and
- `PCIe Allocating Write Flows = Non-Allocating` without xADR

For benchmarking purposes, DRAM is used (instead of PMem) as the source (for reads) and as the target (for writes) what does not change the mechanics of both reading and writing.

**Note**: Both configurations achieve *Direct Write to PMem* capability in two different ways.

{{config.bw}}

<h3 id="dram-read-bw" class="page-break">Read</h3>

Benchmarking the `rpma_read()` operation.

{{figure.dram_read.bw_bs | figure}}

{{figure.dram_read.bw_threads | figure}}

<h3 id="dram-write-bw" class="page-break">Write</h3>

Benchmarking writing data persistently to **the RPMA Target** using *Appliance Persistency Method*. **APM** uses `rpma_flush()` following a sequence of `rpma_write()` operations to provide the remote persistency. This method requires **the RPMA Target** to be capable of *Direct Write to PMem* (**DW2PMem**; for details please see [Direct Write to PMem​​](https://pmem.io/rpma/documentation/basic-direct-write-to-pmem.html)).

For more details on **APM** please see: "[Persistent Memory Replication Over Traditional RDMA Part 1: Understanding Remote Persistent Memory](https://software.intel.com/content/www/us/en/develop/articles/persistent-memory-replication-over-traditional-rdma-part-1-understanding-remote-persistent.html)" Chapter "Two Remote Replication Methods".

{{figure.dram_write.bw_bs | figure}}

{{figure.dram_write.bw_threads | figure}}

{% endif %}
