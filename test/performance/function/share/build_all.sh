#!/bin/sh

cd ..

for dir in */; do
    if [ -f "${dir}Makefile" ] || [ -f "${dir}makefile" ]; then
        echo "========================================"
        echo "Folder: ${dir}"
        echo "========================================"

        (cd "$dir" && make)

    else
        echo "Not found ${dir}"
    fi
done

echo "Finish"
