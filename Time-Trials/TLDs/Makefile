all: calculate-alg2.png validate-alg2.png


calculate-alg2.png: calculate-alg2.plotcmd calculate-alg2.log
	gnuplot < calculate-alg2.plotcmd > $@_
	mv $@_ $@

validate-alg2.png: validate-alg2.plotcmd validate-alg2.log
	gnuplot < validate-alg2.plotcmd > $@_
	mv $@_ $@
