c2c_ROOT="$(dirname "$PWD")"/out
LD_LIBRARY_PATH=$c2c_ROOT/lib $c2c_ROOT/bin/c2cd --config-file=c2c.conf
