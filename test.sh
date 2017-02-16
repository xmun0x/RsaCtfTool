#!/bin/bash

# Test all the pub and ciphers
echo "Test hastads"
python RsaCtfTool.py --publickey examples/small_exponent.pub --verbose --private --uncipher examples/small_exponent.cipher
echo "Test noveltyprimes"
python RsaCtfTool.py --publickey examples/elite_primes.pub --verbose --private
echo "Test small_q"
python RsaCtfTool.py --publickey examples/small_q.pub --verbose --private --uncipher examples/small_q.cipher
echo "Test wiener"
python RsaCtfTool.py --publickey examples/wiener.pub --verbose --private --uncipher examples/wiener.cipher
echo "Test commonfactors"
python RsaCtfTool.py --publickey examples/common_factor.pub --verbose --private --uncipher examples/common_factor.cipher
echo "Test fermat"
python RsaCtfTool.py --publickey examples/close_primes.pub --verbose --private --uncipher examples/close_primes.cipher
echo "Test fermat2"
python RsaCtfTool.py --publickey examples/fermat.pub --verbose --private
echo "Test pastctfprimes"
python RsaCtfTool.py --publickey examples/pastctfprimes.pub --verbose --private
echo "Test SIQS"
python RsaCtfTool.py --publickey examples/siqs.pub --verbose --private
echo "Test createpub"
python RsaCtfTool.py --createpub --n 8616460799 --e 65537
echo "Test createpub with no modulus should raise exception"
python RsaCtfTool.py --createpub --e 3
echo "Createpub into Crack feedback"
python RsaCtfTool.py --createpub --n 163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013 --e 65537 > /tmp/crackme.txt
python RsaCtfTool.py --publickey /tmp/crackme.txt --verbose --private
rm -f /tmp/crackme.txt
