.. SPDX-License-Identifier: GPL-2.0

.. raw:: latex

	\renewcommand\thesection*
	\renewcommand\thesubsection*
	\kerneldocCJKon
	\kerneldocBeginSC{

.. _linux_doc_zh:

中文翻译
========


.. note::

   **翻译计划:**
   内核中文文档欢迎任何翻译投稿，特别是关于内核用户和管理员指南部分。

这是中文内核文档树的顶级目录。内核文档，就像内核本身一样，在很大程度上是一
项正在进行的工作；当我们努力将许多分散的文件整合成一个连贯的整体时尤其如此。
另外，随时欢迎您对内核文档进行改进；如果您想提供帮助，请加入vger.kernel.org
上的linux-doc邮件列表，并按照Documentation/translations/zh_CN/how-to.rst的
指引提交补丁。提交补丁之前请确保执行"make htmldocs”后无与翻译有关的异常输出。

如何翻译内核文档
----------------

翻译文档本身是一件很简单的事情，但是提交补丁需要注意一些细节，为了保证内核中文文档的高质量可持续发展，提供了一份翻译指南。

.. toctree::
   :maxdepth: 1

   how-to.rst

与Linux 内核社区一起工作
------------------------

与内核开发社区进行协作并将工作推向上游的基本指南。

.. toctree::
   :maxdepth: 1

   process/development-process
   process/submitting-patches
   行为准则 <process/code-of-conduct>
   maintainer/index
   完整开发流程文档 <process/index>

内部API文档
-----------

开发人员使用的内核内部交互接口手册。

.. toctree::
   :maxdepth: 1

   core-api/index
   driver-api/index
   subsystem-apis
   内核中的锁 <locking/index>

开发工具和流程
--------------

为所有内核开发人员提供有用信息的各种其他手册。

.. toctree::
   :maxdepth: 1

   process/license-rules
   doc-guide/index
   dev-tools/index
   dev-tools/testing-overview
   kernel-hacking/index
   rust/index

TODOList:

* trace/index
* fault-injection/index
* livepatch/index

面向用户的文档
--------------

下列手册针对
希望内核在给定系统上以最佳方式工作的*用户*，
和查找内核用户空间API信息的程序开发人员。

.. toctree::
   :maxdepth: 1

   admin-guide/index
   admin-guide/reporting-issues.rst
   userspace-api/index
   内核构建系统 <kbuild/index>

TODOList:

* 用户空间工具 <tools/index>

也可参考独立于内核文档的 `Linux 手册页 <https://www.kernel.org/doc/man-pages/>`_ 。

固件相关文档
------------

下列文档描述了内核需要的平台固件相关信息。

.. toctree::
   :maxdepth: 2

   devicetree/index

TODOList:

* firmware-guide/index

体系结构文档
------------

.. toctree::
   :maxdepth: 2

   arch/index

其他文档
--------

有几份未分类的文档似乎不适合放在文档的其他部分，或者可能需要进行一些调整和/或
转换为reStructureText格式，也有可能太旧。

.. toctree::
   :maxdepth: 2

   staging/index

术语表
------

.. toctree::
   :maxdepth: 1

   glossary


索引和表格
----------

* :ref:`genindex`

.. raw:: latex

	}\kerneldocEndSC
