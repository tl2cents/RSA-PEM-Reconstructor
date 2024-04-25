
Place a `solver` built from [rsa-bits](/rsa-bits) in this directory.

## Example

Solve `SIGINT` :

``` bash
$ ./solver -i SIGINT-input.txt  -m SIGINT-mask.txt -v
```

Solve `SPARSE`:

Simply running `./solver -i sparse_input.txt -m sparse_mask.txt -v` will fails and run out of memory at depth about 870. Instead, we can turn on the coppersmith method by:

```bash
$ ./solver -i sparse_input.txt -m sparse_mask.txt -c 0.8 -q 1
```

Then it's time for a coppersmith solver.
