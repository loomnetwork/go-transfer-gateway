# transfer-gateway

Transfer Gateway Go contracts and Oracles that are built into `loomchain` PlasmaChain builds.

## Building

The only thing in this repo you can build are the unit tests, the Oracles themselves should be
built via the `loomchain` Makefile, just ensure this repo is checked out to the same `GOPATH` as
`loomchain`.

To run the tests in this repo you'll need to install the dependencies, there are two options.

### Option 1: Reuse `loomchain` GOPATH (you probably want this)

If you want to use the same `GOPATH` your `loomchain` checkout is in you can do so by only
installing the vendored dependencies:

```bash
make vendor-deps
```

### Option 2: Set up new GOPATH (for running tests on CI)

If you want to setup a separate `GOPATH` just for building the tests you can do so by running:

```bash
make deps
```
