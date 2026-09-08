# INF2005 ACW1 -- Demo Test Evidence Report

Total cases: 29  |  Passed: 29  |  Failed: 0

| Case ID | Cover | Category | Description | Verdict | Expected | Result |
|---|---|---|---|---|---|---|
| IMG-CAP-01 | image | capacity-check | Cover capacity=114574B at 1 LSB, message=119574B | Rejected: Payload larger than cover object capacity | Rejected: Payload larger than cover object capacity | PASS |
| IMG-POS-01 | image | positive | Short message (learning objective), LSB=1 | Authentic | Authentic | PASS |
| IMG-POS-02 | image | positive-send-receive | Large message (project overview), LSB=4, sent A->B then verified by B | Authentic | Authentic | PASS |
| IMG-POS-03 | image | positive | Custom confidential payload, LSB=8 | Authentic | Authentic | PASS |
| IMG-NEG-01 | image | negative | Cover pixels tampered after signing | Tampered | Tampered | PASS |
| IMG-NEG-02 | image | negative | Verifier supplies the wrong shared secret key | Cannot Verify | Cannot Verify | PASS |
| IMG-NEG-03 | image | negative | File signed with an untrusted private key | Signature Invalid | Signature Invalid | PASS |
| IMG-NEG-04 | image | negative | Original cover object with no embedded payload | Payload Missing | Payload Missing | PASS |
| IMG-NEG-05 | image | negative | Header engineered to advertise an out-of-range start offset | Wrong Start Location | Wrong Start Location | PASS |
| IMG-LSB-1 | image | lsb-matrix | Selectable LSB depth = 1 | Authentic | Authentic | PASS |
| IMG-LSB-2 | image | lsb-matrix | Selectable LSB depth = 2 | Authentic | Authentic | PASS |
| IMG-LSB-3 | image | lsb-matrix | Selectable LSB depth = 3 | Authentic | Authentic | PASS |
| IMG-LSB-4 | image | lsb-matrix | Selectable LSB depth = 4 | Authentic | Authentic | PASS |
| IMG-LSB-5 | image | lsb-matrix | Selectable LSB depth = 5 | Authentic | Authentic | PASS |
| IMG-LSB-6 | image | lsb-matrix | Selectable LSB depth = 6 | Authentic | Authentic | PASS |
| IMG-LSB-7 | image | lsb-matrix | Selectable LSB depth = 7 | Authentic | Authentic | PASS |
| IMG-LSB-8 | image | lsb-matrix | Selectable LSB depth = 8 | Authentic | Authentic | PASS |
| AUD-CAP-01 | audio | capacity-check | Cover capacity=26936B at 1 LSB, message=31936B | Rejected: Payload larger than cover object capacity | Rejected: Payload larger than cover object capacity | PASS |
| AUD-POS-01 | audio | positive | Short message (learning objective), LSB=2 | Authentic | Authentic | PASS |
| AUD-POS-02 | audio | positive-send-receive | Large message (project overview), LSB=5, sent A->B then verified by B | Authentic | Authentic | PASS |
| AUD-POS-03 | audio | positive | Custom confidential payload, LSB=8 | Authentic | Authentic | PASS |
| AUD-NEG-01 | audio | negative | Cover samples tampered after signing | Tampered | Tampered | PASS |
| AUD-NEG-02 | audio | negative | Verifier supplies the wrong shared secret key | Cannot Verify | Cannot Verify | PASS |
| AUD-NEG-03 | audio | negative | File signed with an untrusted private key | Signature Invalid | Signature Invalid | PASS |
| AUD-NEG-04 | audio | negative | Original cover object with no embedded payload | Payload Missing | Payload Missing | PASS |
| AUD-LSB-1 | audio | lsb-matrix | Selectable LSB depth = 1 | Authentic | Authentic | PASS |
| AUD-LSB-3 | audio | lsb-matrix | Selectable LSB depth = 3 | Authentic | Authentic | PASS |
| AUD-LSB-6 | audio | lsb-matrix | Selectable LSB depth = 6 | Authentic | Authentic | PASS |
| AUD-LSB-8 | audio | lsb-matrix | Selectable LSB depth = 8 | Authentic | Authentic | PASS |