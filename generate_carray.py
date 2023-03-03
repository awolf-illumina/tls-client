import sys

def binary_to_c_array(input_file, output_file, array_name):
    with open(input_file, 'rb') as f:
        data = f.read()

    with open(output_file, 'w') as f:
        f.write("const unsigned char %s[] = {\n" % array_name)

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_values = ["0x{:02X}".format(b) for b in chunk]
            f.write("    " + ", ".join(hex_values) + ",\n")

        f.write("};\n")


def main():
    input_file = sys.argv[1]
    output_file = "output.c"
    array_name = "array"

    binary_to_c_array(input_file, output_file, array_name)


main()