C2C_ROOT="$(dirname "$PWD")"
C2C_ROOT="$(dirname "$C2C_ROOT")"/out-qt
LD_LIBRARY_PATH='$C2C_ROOT/lib;/opt/Qt/5.12.2/gcc_64/lib' $C2C_ROOT/bin/qc2c
