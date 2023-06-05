#!/bin/sh
if (( $# != 1 )); then
    >&2 echo "Usage: $0 file.csv"
    exit 2
fi

for i in {2..62}
do
   gnuplot -p -e "in_filename='$1'; out_filename='chart_col_$i.png'; column=$i;" csv.gnuplot
done
