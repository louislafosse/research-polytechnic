TARGET = slides
BUILD_DIR = build
LATEX = pdflatex
BIBTEX = bibtex
LATEX_FLAGS = -interaction=nonstopmode -file-line-error -halt-on-error -output-directory=$(BUILD_DIR)

all: $(BUILD_DIR)/$(TARGET).pdf

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(TARGET).pdf: $(TARGET).tex | $(BUILD_DIR)
	@echo "Building $(TARGET).pdf in $(BUILD_DIR)/..."
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex
	@if grep -q '\\bibliography' $(TARGET).tex; then \
		echo "Running bibtex..."; \
		cd $(BUILD_DIR) && $(BIBTEX) $(TARGET); \
		cd .. && $(LATEX) $(LATEX_FLAGS) $(TARGET).tex; \
	fi
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex
	@echo "Build complete: $(BUILD_DIR)/$(TARGET).pdf"

quick: $(TARGET).tex | $(BUILD_DIR)
	$(LATEX) $(LATEX_FLAGS) $(TARGET).tex

clean:
	@echo "Removing $(BUILD_DIR)/ directory..."
	rm -rf $(BUILD_DIR)
	@echo "Removing auxiliary files in current directory..."
	rm -f $(TARGET).aux $(TARGET).log $(TARGET).out $(TARGET).toc
	rm -f $(TARGET).nav $(TARGET).snm $(TARGET).vrb
	rm -f $(TARGET).fdb_latexmk $(TARGET).fls $(TARGET).synctex.gz
	rm -f $(TARGET).bbl $(TARGET).blg $(TARGET).run.xml $(TARGET).bcf
	rm -f $(TARGET).pdf

distclean: clean

view: $(BUILD_DIR)/$(TARGET).pdf
	xdg-open $(BUILD_DIR)/$(TARGET).pdf &

watch:
	@echo "Watching for changes... (Ctrl+C to stop)"
	@while true; do \
		inotifywait -e modify $(TARGET).tex 2>/dev/null && make quick; \
	done

.PHONY: all quick clean distclean view watch
