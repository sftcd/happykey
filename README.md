# happykey

Playing with implementing
[draft-irtf-cfrg-hpke](https://tools.ietf.org/html/draft-irtf-cfrg-hpke) using
OpenSSL.

Note: This is pretty crap for now, just messing about a bit with loadsa current
code that needs re-organising and much more;-)

Currently, (20191126) ``hpke_enc()`` does produce an output, but I've no idea
if that's correct or not, so I'm currently working on a way to integrate the
[test-vectors](test-vectors.json) from 
[the CFRG repo](https://github.com/cfrg/draft-irtf-cfrg-hpke).  
Once that seems to be doing something (and I've yet to load the JSON into some
C struct;-) then I'll start to refactor the ``hpke_enc()`` code to be more
sensible.
