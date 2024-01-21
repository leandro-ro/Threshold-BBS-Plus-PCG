# Psuedorandom Correlation Generator for Threhsold BBS+

## File Structure
- `dpf`: Holds interface definitions and their implementation for Distributed Point Functions (DPF).
    - `optreedpf`: Implements a Two-Party Tree-Based DPF as described in [Function Secret Sharing: Improvements and Extensions](https://eprint.iacr.org/2018/707.pdf).
        - `optreedpf.go`
        - `optreedpf_test.go`
    - `dpf_interface.go`
    - `dpf_utils.go`
    - `dpf_utils_test.go`
- `dspf`: Aggregates multiple DPFs into shared Multipoint Functions i.e. Distributed Sum of Point Functions (DSPF).
    - `dspf.go`
    - `dspf_key.go`
    - `dspf_test.go`
    - `dspf_util.go`
- `pcg`
    - `bench`
        - `eval_combined_test.go`
        - `eval_separate_test.go`
    - `poly`: Implements efficient polynomial operations via maps.
        - `fft.go`: Implements Fast Fourier Transform (FFT) for high-degree polynomial multiplication.
        - `poly.go`
        - `poly_test.go`:
    - `pcg.go`: Implements the PCG. Also provides and optimized PCG Eval for n-out-of-n case.
    - `pcg_test.go`: Holds the end-to-end tests for the PCG Evaluation.
    - `seed.go`
    - `tuple.go`
    - `tuple_test.go`
    - `utils.go`
    - `utils_test.go`
## Usage
### Tests

Run the entire test suite from the root directory with:
```bash
go test ./...
```
End-to-End tests have been configured with smaller security parameters for faster execution. To run these tests specifically:

- For n-out-of-n optimized PCG Evaluation:
    ```bash
    go test -run=TestPCGCombinedEnd2End ./pcg
    ```
- For tau-out-of-n PCG Evaluation:
    ```bash
    go test -run=TestPCGSeparateEnd2End ./pcg
    ```
### Benchmarks

Benchmarks for individual components can be found within the `_test.go` files of their respective directories. To benchmark the PCG Evaluation use:

```bash
go test -bench=. ./pcg/bench
```
For more granular benchmarking, such as assessing the performance for a specific subset of parameters, you can specify which benchmarks to run. For example, to benchmark the 2-out-of-3 case for all N, execute:
```bash
go test -bench=BenchmarkOpEvalSeparate2outof3_N ./pcg/bench
```
or to benchmark the 10-out-of-10 case for a specific N=15, execute:
```bash
go test -bench=BenchmarkOpEvalCombined10outof10_N15 ./pcg/bench
```
