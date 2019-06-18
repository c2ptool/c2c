c2c_ROOT="$(dirname "$PWD")"
c2c_ROOT="$(dirname "$c2c_ROOT")"/out
LD_LIBRARY_PATH=$c2c_ROOT/lib $c2c_ROOT/bin/client 127.0.0.1 9002
