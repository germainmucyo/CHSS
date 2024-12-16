# Variables
PYTHON=/bin/python3
MAIN_SCRIPT=/home/germainmucyo/aes/lab-3-germainmucyo/submission/dfa_aes.py
EXTRA_CREDIT_PART1=/home/germainmucyo/aes/lab-3-germainmucyo/submission/extra_1_By_col.py
EXTRA_CREDIT_PART2=/home/germainmucyo/aes/lab-3-germainmucyo/submission/extra_2_8th_row.py

# Default target to run the main DFA test
run:
	@echo "Running DFA AES..."
	@$(PYTHON) $(MAIN_SCRIPT)

# Run the column-based fault model (Extra Credit Part 1)
run_column_model:
	@echo "Running Extra Credit Part 1 (Column-based Fault Model)..."
	@$(PYTHON) $(EXTRA_CREDIT_PART1)

# Run the 8th-round MixColumn fault model (Extra Credit Part 2)
run_mixcolumn_model:
	@echo "Running Extra Credit Part 2 (8th-round MixColumn Fault Model)..."
	@$(PYTHON) $(EXTRA_CREDIT_PART2)

# Run all scripts sequentially
run_all:
	@echo "Running DFA Test and Extra Credit Parts..."
	@$(PYTHON) $(MAIN_SCRIPT)
	@$(PYTHON) $(EXTRA_CREDIT_PART1)
	@$(PYTHON) $(EXTRA_CREDIT_PART2)

# Clean up cache and temporary files (if any)
clean:
	@rm -rf __pycache__
	@echo "Cleaned up."
