#!/bin/bash

# Название итогового файла
OUTPUT_FILE="../full_project_context.txt"

# Очищаем файл, если он уже существует
> "$OUTPUT_FILE"

# Ищем все .rs файлы, исключая директорию target
find . -type d -name "target" -prune -o -type f -name "*.rs" -print | while read -r file; do
    echo "--- FILE: $file ---" >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    echo -e "\n\n" >> "$OUTPUT_FILE"
    echo "Добавлен: $file"
done

echo "Готово! Весь код собран в $OUTPUT_FILE"
