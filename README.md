# [Certificate Misissuance - A Review Paper][4]

 Publication [Tracking Certificate Misissuance in the Wild](https://doi.org/10.1109/SP.2018.00015) by Deepak Kumar, Zhengping Wang, Matthew Hyder, Joseph Dickinson, Gabrielle Beck, David Adrian, Joshua Mason, Zakir Durumeric, J. Alex Halderman, Michael Bailey

## Description

In their paper, Kumar et al. showed that certificate authorities regularly make errors when issuing certificates. This project reproduces their results with the same methodology using [zlint][2] and the snapshot used in the original paper.

## Experiment Setup

### Experiment Content

I am going to reproduce the basic results from the original paper, namely TABLE I, TABLE III and Fig 2.

### Hardware/Software

Since the tool `zlint` is open source and can be used as a Go library, I wrote a small application to verify the results using the exact same version of `zlint` as the authors in the original paper. The hardware used to reproduce is a virtual machine instance with 8 cores and about 48 GB of RAM. The 2.5 TB large snapshot is stored on normal hard disk drive.

## Experiment Assumptions

It is assumed that the snapshot I was provided is the original one and the version of `zlint` is the one used in the original paper (since it still receives updates to this day of writing this paper).

## Preconditions

Any person that reproduces this experiment will need research access by Censys to download a recent snapshot. An existing Go installation is required. The proprietary data can be obtained by first getting [research access][3] to Censys certificate scan snapshots and then requesting the data from Mr. Kumar "dkumar11 [at] illinois [dot] edu" with the attached permission grant from Censys. 

## Experiment Steps

As the original snapshot is not available anymore, I requested and was being granted research access by Censys and then requested the original snapshot from Mr. Kumar. He confirmed the `SHA1` hash value and provided me with the version (hash of master branch) of `zlint`.

Since the tool `zlint` is open source and can be used as a Go library, I wrote a small application to verify the results using the exact same version of `zlint` as the authors in the original paper. It reads the text files from snapshot in parallel, collecting all certificates that were valid on 23.07.2017. The certificates that have parseable asn1 structures are being processed each one-by-one by `zlint`, saving the relevant processing result data into a comma separated file which in a next step is imported into some PostgreSQL relational database.

The data then is aggregated using structured query language, trying to reproduce the results of the paper.

## Acknowledgements

I thank Wilfried Mayer for the technical support and virtual machine help during the verification process. Also, I thank Edgar Weippl for the reliable supervision. This work was supported in part by SBA Research gGmbH.



[1]: https://kumarde.com/papers/misissuance.pdf
[2]: https://github.com/zmap/zlint
[3]: https://support.censys.io/getting-started/research-access-to-censys-data
[4]: https://checkresearch.org/Experiment/View/ed8561aa-540e-42d9-8b4f-d328a3fc2d5c