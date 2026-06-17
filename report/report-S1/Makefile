# Makefile for LaTeX Report

TARGET = report
BUILD_DIR = build
SRC_DIR = src

# LaTeX compilation commands
LATEX = pdflatex
BIBTEX = bibtex
LATEX_FLAGS = -interaction=nonstopmode -file-line-error -halt-on-error -output-directory=$(BUILD_DIR)

# Source files
TEX_FILES = $(TARGET).tex $(wildcard $(SRC_DIR)/*.tex)
BIB_FILES = $(TARGET).bib

# Output PDF
PDF = $(BUILD_DIR)/$(TARGET).pdf

.PHONY: all clean view draft

# Default target
all: $(PDF)

# Build PDF with bibliography
$(PDF): $(TEX_FILES) $(BIB_FILES) | $(BUILD_DIR)
	cp $(BIB_FILES) $(BUILD_DIR)/
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex
	cd $(BUILD_DIR) && $(BIBTEX) $(TARGET); cd ..
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET).aux $(TARGET).log $(TARGET).bbl $(TARGET).blg $(TARGET).out
	rm -f $(TARGET).fdb_latexmk $(TARGET).fls $(TARGET).synctex.gz
	rm -f $(TARGET).pdf $(TARGET).toc $(TARGET).lof $(TARGET).lot

# View PDF (Linux)
view: $(PDF)
	xdg-open $(PDF) 2>/dev/null || open $(PDF) 2>/dev/null || echo "Please open $(PDF) manually"

# Quick build without bibliography (faster for draft)
draft: $(TEX_FILES) | $(BUILD_DIR)
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex
