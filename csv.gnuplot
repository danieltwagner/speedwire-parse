set datafile separator ','

set xdata time # tells gnuplot the x axis is time data
set timefmt "%Y-%m-%d %H:%M:%S" # specify our time string format
set format x "%H:%M:%S" # otherwise it will show only MM:SS

set terminal png size 1200,800 enhanced
set output out_filename

set key autotitle columnhead # use the first line as title
plot in_filename using 1:column with lines
