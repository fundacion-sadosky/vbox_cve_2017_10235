*******************************************************
CVE-2017-10235: VirtualBox E1000 device buffer overflow
*******************************************************

Introduction
============

The following document details a bug found in VirtualBox v5.1.22 (now fixed in v5.1.24), in the guest device emulation component ``DevE1000`` (*Intel 82540EM Ethernet Controller Emulation*), in the function ``e1kFallbackAddToFrame``, which leads to a buffer overflow in the host when the guest OS is controlled by an attacker.

The bug was acknowledged by Oracle in the `CPU of July 2017
<http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixOVIR/>`_ with the issued `CVE-2017-10235
<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-10235/>`_.

The vulnerability was corroborated with both a Linux (Ubuntu 16.04) and a Windows (v8.1) host running a Linux (also Ubuntu 16.04) guest, but the vulnerability could be triggered in many different host/guest combinations. In all scenarios the default network configuration is assumed: only one network adapter **attached to NAT** of type **Intel PRO/1000 MT Desktop (82540EM)**.

Since control structures (including function pointers) can be overwritten with attacker controlled data, it is safe to assume that remote code execution could be achieved in many scenarios. Oracle assigned a low CVSS score to this bug because it regarded that it had a ``None`` confidentiality risk and a ``low`` integrity, which we believe does not reflect the full compromising potentiality of this bug (an explanation for the possibility of RCE is given below).


Bug description and exploitation
================================

The VirtualBox code that implements the emulation of the Intel 82540EM Ethernet Controller, in ``src/VBox/Devices/Network/DevE1000.cpp``, has part of the functionality of the hardware TCP Segmentation in the function ```e1kFallbackAddToFrame()`` https://www.virtualbox.org/browser/vbox/trunk/src/VBox/Devices/Network/DevE1000.cpp?rev=64966#L4286`_:

.. code-block:: c

   static int e1kFallbackAddToFrame(PE1KSTATE pThis, E1KTXDESC *pDesc,
                                    bool fOnWorkerThread)
   {
   #ifdef VBOX_STRICT
       PPDMSCATTERGATHER pTxSg = pThis->CTX_SUFF(pTxSg);
       Assert(e1kGetDescType(pDesc) == E1K_DTYP_DATA);
       Assert(pDesc->data.cmd.fTSE);
       Assert(!e1kXmitIsGsoBuf(pTxSg));
   #endif

       uint16_t u16MaxPktLen = pThis->contextTSE.dw3.u8HDRLEN +
                               pThis->contextTSE.dw3.u16MSS;
       Assert(u16MaxPktLen != 0);
       Assert(u16MaxPktLen < E1K_MAX_TX_PKT_SIZE);

This function correctly checks that the max TX packet length (``u16MaxPktLen``) is below the standard maximum of 16288 bytes (``E1K_MAX_TX_PKT_SIZE``), but does it in the form of an ``Assert()`` macro that will be disabled in a release build, effectively leaving the check useless for the end user. This can be contrasted to the analogous function ``e1kAddToFrame()``, which enforces the check with an explicit ``if`` instead of the ``Assert()``:

.. code-block:: c

   static bool e1kAddToFrame(PE1KSTATE pThis, RTGCPHYS PhysAddr,
                             uint32_t cbFragment)
   {
       PPDMSCATTERGATHER   pTxSg    = pThis->CTX_SUFF(pTxSg);
       bool const          fGso     = e1kXmitIsGsoBuf(pTxSg);
       uint32_t const      cbNewPkt = cbFragment + pThis->u16TxPktLen;

       if (RT_UNLIKELY( !fGso && cbNewPkt > E1K_MAX_TX_PKT_SIZE ))
       {
           E1kLog(("%s Transmit packet is too large: %u > %u(max)\n",
                   pThis->szPrf, cbNewPkt, E1K_MAX_TX_PKT_SIZE));
           return false;
       }

The difference between the use of the normal function and the fallback (decided in ``e1kXmitDesc()``) depends on two factors, that the TSE flag is enabled in the descriptors (controlled by the guest) and that the GSO is disabled. The latter depends on many factors, and hence there are many ways to disable it, but the most convenient is to enable the loopback mode, which is configured through the Receive Control Register (in the ``RCTL.LBM`` bits), also controlled by the guest OS.

Enabling the loopback mode will make ``e1kXmitAllocBuf()`` use the ``aTxPacketFallback`` buffer (*Transmit packet buffer use for TSE fallback and loopback*) for the allocation of the PDM scatter/gather buffer, with the mentioned length of 16288 bytes (``E1K_MAX_TX_PKT_SIZE``), and to signal that GSO will be disabled, by setting a ``NULL`` in ``pvUser``.

.. code-block:: c

   if (RT_LIKELY(GET_BITS(RCTL, LBM) != RCTL_LBM_TCVR))
   {

      ...

   }
   else
   {
     /* Create a loopback using the fallback buffer and preallocated SG. */
     AssertCompileMemberSize(E1KSTATE, uTxFallback.Sg, 8 * sizeof(size_t));
     pSg = &pThis->uTxFallback.Sg;
     pSg->fFlags      = PDMSCATTERGATHER_FLAGS_MAGIC |
                        PDMSCATTERGATHER_FLAGS_OWNER_3;
     pSg->cbUsed      = 0;
     pSg->cbAvailable = 0;
     pSg->pvAllocator = pThis;
     pSg->pvUser      = NULL; /* No GSO here. */
     pSg->cSegs       = 1;
     pSg->aSegs[0].pvSeg = pThis->aTxPacketFallback;
     pSg->aSegs[0].cbSeg = sizeof(pThis->aTxPacketFallback);
   }

This will cause the call to the function ``e1kXmitIsGsoBuf()`` (inside ``e1kXmitDesc()``) to return ``False`` and, with the TSE enabled in the data descriptor, the execution flow will go to ``e1kFallbackAddToFrame()`` (instead of the safer ``e1kAddToFrame()``, with the correct check).

.. code-block:: c

  /*
   * Add the descriptor data to the frame.  If the frame is complete,
   * transmit it and reset the u16TxPktLen field.
   */
  if (e1kXmitIsGsoBuf(pThis->CTX_SUFF(pTxSg)))
  {

    ...

  }
  else if (!pDesc->data.cmd.fTSE)
  {

    ...

  }
  else
  {
      STAM_COUNTER_INC(&pThis->StatTxPathFallback);
      rc = e1kFallbackAddToFrame(pThis, pDesc, fOnWorkerThread);
  }

Inside ``e1kFallbackAddToFrame()``, with the aforementioned check disabled in a release build, the MSS can be set arbitrarily large (up to 64K minus the HDRLEN), hence allowing an arbitrarily large ``DTALEN`` to be passed to ``e1kFallbackAddSegment()``:

.. code-block:: c

   /*
   * Carve out segments.
   */
   int rc;
   do
   {
     /* Calculate how many bytes we have left in this TCP segment */
     uint32_t cb = u16MaxPktLen - pThis->u16TxPktLen;
     if (cb > pDesc->data.cmd.u20DTALEN)
     {
         /* This descriptor fits completely into current segment */
         cb = pDesc->data.cmd.u20DTALEN;
         rc = e1kFallbackAddSegment(pThis, pDesc->data.u64BufAddr, cb,
                     pDesc->data.cmd.fEOP /*fSend*/, fOnWorkerThread);

The function ``e1kFallbackAddSegment()`` will use this value (now as argument ``u16Len``) to copy from guest memory into the buffer ``aTxPacketFallback`` in host memory (through ``PDMDevHlpPhysRead()``) without further checks to this length, thus causing the buffer overflow (of a buffer capacity of 16288 bytes with a memory size of up to 64K).

.. code-block:: c

  static int e1kFallbackAddSegment(PE1KSTATE pThis, RTGCPHYS PhysAddr,
                     uint16_t u16Len, bool fSend, bool fOnWorkerThread)
  {
      int rc = VINF_SUCCESS;
      /* TCP header being transmitted */
      struct E1kTcpHeader *pTcpHdr = (struct E1kTcpHeader *)
              (pThis->aTxPacketFallback + pThis->contextTSE.tu.u8CSS);
      /* IP header being transmitted */
      struct E1kIpHeader *pIpHdr = (struct E1kIpHeader *)
              (pThis->aTxPacketFallback + pThis->contextTSE.ip.u8CSS);

      E1kLog3(("%s e1kFallbackAddSegment: Length=%x, remaining payload=%x,
               header=%x, send=%RTbool\n", pThis->szPrf, u16Len,
               pThis->u32PayRemain, pThis->u16HdrRemain, fSend));
      Assert(pThis->u32PayRemain + pThis->u16HdrRemain > 0);

      PDMDevHlpPhysRead(pThis->CTX_SUFF(pDevIns), PhysAddr,
                        pThis->aTxPacketFallback + pThis->u16TxPktLen, u16Len);

To make this vulnerability more predisposed to a RCE, it has to be noted that the variable just after the buffer is its index (``u16TxPktLen``), used to write on it (as an offset on the argument of ``PDMDevHlpPhysRead()``). So controlling this value with an initial buffer overflow (caused by a first data descriptor of length ``E1K_MAX_TX_PKT_SIZE`` + 2 bytes) would then allow to write (in a second call to ``PDMDevHlpPhysRead()`` with a second data descriptor) any memory address up to 64K of distance from the buffer, without being necessary to overwrite all the memory in-between  (which would make the attack more complicated, trying to avoid a potential crash).

A (minor) complication in this attack vector is worth mentioning for completeness: there is what seems like a bug in ``e1kXmitAllocBuf()``, where in the case of being in loopback mode, ``cbTxAlloc`` (*Number of bytes in next packet*) is not reseted to zero, as it is done in the normal case ( in the other branch of its ``if``). This causes the thread to get stuck in the ``while`` loop of ``e1kLocateTxPacket()`` (inside ``e1kXmitPending()``):

.. code-block:: c

   while (e1kLocateTxPacket(pThis))
   {
       fIncomplete = false;
       /* Found a complete packet, allocate it. */
       rc = e1kXmitAllocBuf(pThis, pThis->fGSO);
       /* If we're out of bandwidth we'll come back later. */
       if (RT_FAILURE(rc))
           goto out;
       /* Copy the packet to allocated buffer and send it. */
       rc = e1kXmitPacket(pThis, fOnWorkerThread);
       /* If we're out of bandwidth we'll come back later. */
       if (RT_FAILURE(rc))
           goto out;
   }

This seems to happen because ``e1kLocateTxPacket()`` prematurely returns with ``True`` in the case where ``cbTxAlloc`` is not zero, and doesn't reach the code that checks if ``iTxDCurrent`` is equal to  ``nTxDFetched`` (the usual case where all descriptors have been processed), which would normally make the function return ``False``, effectively terminating the aforementioned loop.

.. code-block:: c

   static bool e1kLocateTxPacket(PE1KSTATE pThis)
   {
       LogFlow(("%s e1kLocateTxPacket: ENTER cbTxAlloc=%d\n",
                pThis->szPrf, pThis->cbTxAlloc));
       /* Check if we have located the packet already. */
       if (pThis->cbTxAlloc)
       {
           LogFlow(("%s e1kLocateTxPacket: RET true cbTxAlloc=%d\n",
                    pThis->szPrf, pThis->cbTxAlloc));
           return true;
       }

This translates to the requirement that the first packet sent to the device (after setting the loopback mode) has to be the one that triggers the overflow, otherwise the VM will hang (ending with a DoS rather than a RCE).


Proof of concept
================

Because the setup of the network device is far from trivial, and to avoid building a custom driver for it, the E1000 driver of a generic Linux kernel was modified to generate the descriptors (both context and data) that trigger the overflow. This modified kernel is attached to this report as a PoC of the vulnerability, it has been tested in an Ubuntu 16.04 guest, causing a crash both in Linux and Windows hosts.


Possible solutions
==================

The main solution to this issue is to convert the checks made as ``Assert()`` in ``e1kFallbackAddToFrame`` to explicit checks as ``if`` statements, that would operate in a release build, similar to what is done in ``e1kAddToFrame()``.

Additional (defensive) checks could also be placed in ``e1kFallbackAddSegment()`` (and similarly in ``e1kAddToFrame``) before the call to ``PDMDevHlpPhysRead()`` to explicitly check for potential overflows of any host buffer with guest memory.
