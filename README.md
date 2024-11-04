# TaiE: Function Identification for Monolithic Firmware

The principal tasks of program analysis, including bug searching and code similarity detection, are executed at the function level. However, the accurate identification of functions within stripped binary files poses a significant challenge. This difficulty is exacerbated by unformatted monolithic firmware images typically found in industrial controlling device, rendering existing methods ineffective due to their dependence on specific metadata, which may be absent.

In this repository, we propose a new function location identification tool that targets on monolithic firmware images, referred to as TaiE. Our scheme recognizes function locationss based on stack characteristics and does not rely on auxiliary information provided by the target file. 

## PUBLICATIONS

[**ICPC '24**] Jintao Huang, Kai Yang, Gaosheng Wang, Zhiqiang Shi, Shichao Lv, and Limin Sun. 2024. TaiE: Function Identification for Monolithic Firmware. In Proceedings of the 32nd IEEE/ACM International Conference on Program Comprehension (ICPC '24). Association for Computing Machinery, New York, NY, USA, 403–414. https://doi.org/10.1145/3643916.3644407

**Citation**

```bibtex
@inproceedings{10.1145/3643916.3644407,
    author = {Huang, Jintao and Yang, Kai and Wang, Gaosheng and Shi, Zhiqiang and Lv, Shichao and Sun, Limin},
    title = {TaiE: Function Identification for Monolithic Firmware},
    year = {2024},
    isbn = {9798400705861},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    url = {https://doi.org/10.1145/3643916.3644407},
    doi = {10.1145/3643916.3644407},
    booktitle = {Proceedings of the 32nd IEEE/ACM International Conference on Program Comprehension},
    pages = {403–414},
    numpages = {12},
    keywords = {function identification, program analysis, monolithic firmware},
    location = {Lisbon, Portugal},
    series = {ICPC '24}
}
```

## Getting Started

### Requirements

1. Python 3.9 (We have only tested `TaiE` with Python 3.9)
2. Python packages: `capstone`, `angr`. Installed with `pip3.9 install capstone angr`

### To get started

1. Configure the required Python environment and install the required packages
2. Clone the master branch
3. Run `python3.9 taie.py -a arml firm.bin` to analyze the firmware of ARM (Little Endian) or `python3.9 taie.py -a armlt firm.bin` for the firmware of ARM-Thumb (Little Endian)

## Known Issues

`TaiE` recursively applies several strategies on the firmware, in some cases, the analyzing process can fell into an infinite loop.
