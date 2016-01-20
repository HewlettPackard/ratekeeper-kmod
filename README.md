## Linux kernel module for the Ratekeeper mechanism

``ratekeeper-kmod`` is a kernel module that implements *Ratekeper*, a link bandwidth
guarantee mechanism for multi-tenant data-centers.

*Ratekeeper* enforces dynamic rate assignments by combining egress and ingress traffic 
control at the end machines with packet drops and explicit feedback notifications. It 
also imposes egress rate limits on remote senders through a distributed control protocol.

For more details on the *Ratekeeper* mechanism please refer to:
<http://www.hpl.hp.com/techreports/2010/HPL-2010-151.html>

## Details

Please see [README](../master/README) file for more information.
