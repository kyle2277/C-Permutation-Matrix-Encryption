#!/bin/bash
# Copyrite (c) Kyle Won, 2021
# Script for testing multithreaded performance of the matrix encryption program 
# Front_Blanc_C. Only tests encryption, as the decryption side of the algorithm
# varies little from the encryption side.
echo "Usage:"
echo "	./run_threads <\$1> <\$2> <\$3> <\$4> <\$5> <\$6> <\$7>"
echo "	\$1 = Path to Font_Blanc_C binary"
echo "	\$2 = Name of test"
echo "	\$3 = File to run tests on"
echo "	\$4 = Number of threads range start (inclusive)"
echo "	\$5 = Number of threads range end (inclusive)"
echo "	\$6 = Encryption matrix dimension (0 if variable)"
echo "	\$7 = Encryption key"
printf "	\$8 = Input redirection file for running Font_Blanc_C with multiple instructions (optional)\n\n"

if [ -z "$1" -o -z "$2" -o -z "$3" -o -z "$4" -o -z "$5" -o -z "$6" -o -z "$7" ]; then
	echo "MISSING ARGUMENTS."
	exit 0
fi

# Sets the number of times each test is run
NUM_RUNS=5

FBC_SOURCE=$1
echo "Font_Blanc_C path: $FBC_SOURCE"
TEST_NAME=$2
echo "Test name: $TEST_NAME"
TEST_FILE=$3
echo "Test file: $TEST_FILE"
START=$4
echo "Thread range start: $START"
END=$5
echo "Thread range end: $END"
DIMENSION=$6
echo "Matrix dimension: $DIMENSION"
KEY=$7
echo "Encryption key: $KEY"
INPUT=$8
if [ -z "$INPUT" ]; then
	echo "Instruction input file: NONE"
else
	echo "Instruction input file: $INPUT"
fi
FBC_OUTPUT="fbc_elapsed_time.txt"
OUTPUT_FILE="run_threads_${TEST_NAME}.csv"
eval "rm -f ${OUTPUT_FILE}"
printf "File:,${TEST_FILE},Thread range:,${START}-${END},Dimension:,${DIMENSION},Key:,${KEY},\n\n" >> $OUTPUT_FILE
for (( i="$START"; i<=$END; i++ ))
do
	printf "${i}," >> $OUTPUT_FILE
	for (( j=0; j<$NUM_RUNS; j++ ))
	do
		if [ -z "$INPUT" ]; then
			COMMAND="$FBC_SOURCE $TEST_FILE -e -t $i -k $KEY -D $DIMENSION"
		else
			COMMAND="$FBC_SOURCE $TEST_FILE -e -t $i -k $KEY -D $DIMENSION -m < $INPUT"
		fi
		printf "\nRUNNING: $COMMAND\n\n"
		eval "$COMMAND"
		# proces output
		ELAPSED_TIME=`cat $FBC_OUTPUT`
		printf "${ELAPSED_TIME}," >> $OUTPUT_FILE
	done
 	printf "\n" >> $OUTPUT_FILE
done
echo "Done."
