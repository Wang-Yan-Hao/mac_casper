#!/bin/sh

# Function to extract the information from typedefs
extract_typedef_info() {
    typedef_line=$1

#     echo $typedef_line
#     echo ""

    # Extract return type
    return_type=$(echo $typedef_line | grep -o '^typedef .* (\*' | sed 's/^typedef \(.*\) (\*$/\1/')
    # Extract function name
    func_name=$(echo "$typedef_line" | sed -n 's/.*(\*\(.*\))(.*/\1/p')
    # Extract parameter list
    param_list=$(echo "$typedef_line" | sed -n 's/.*(\(.*\));/\1/p')

#     echo "Return type: $return_type"
#     echo "Function name: $func_name"
#     echo "Parameters: $param_list"
#     echo ""

    if [ "$return_type" = "void" ] || echo "$param_list" | grep -qv "cred"; then
        echo "// this need to care" >> output.txt
    fi

    # Append the output to output.txt
    echo "static $return_type
$func_name ($param_list) {
    if (cred == NULL)
        return 0;
    if (cred->cr_ruid == CASPER_DNS_UID)
        return EACCES;
    return 0;
}" >> output.txt

}

# Main script logic
input_file="$1"
while read -r line; do
    if echo "$line" | grep -q "typedef"; then
        last_char=$(echo "$line" | sed 's/.*\(.\)/\1/')
        typedef_block="$line"
        if [ "$last_char" = ";" ]; then
            typedef_block="$line"
        else
            # Loop through the lines until the next typedef
            while read -r next_line; do
                # Check for next typedef or end of block
                last_char=$(echo "$next_line" | sed 's/.*\(.\)/\1/')
                typedef_block="$typedef_block $next_line"

#                 echo "last_char"
#                 echo $last_char
#                 echo ""

                if [ "$last_char" = ";" ]; then
                    break
                fi
            done
        fi
        extract_typedef_info "$typedef_block"
    fi
done < "$input_file"
