import sys

import svd2py

if __name__ == '__main__':
    file_path = sys.argv[1:]
    if not file_path:
        print('Please provide an svd file!')
    else:
        print(f'parsing svd file... {file_path[0]}')
        parser = svd2py.SvdParser()
        result = parser.convert(file_path[0])
        peripherals = result['device']['peripherals']['peripheral']
        for peripheral in peripherals:
            per_name = peripheral['name']
            per_desc = peripheral['description']
            per_base_addr = peripheral['baseAddress']
            print(f'peripheral... {hex(per_base_addr)} @ {per_name} {per_desc}')
            per_addr_blocks = peripheral['addressBlock']
            for addr_block in per_addr_blocks:
                ablk_offset = addr_block['offset']
                ablk_size = addr_block['size']
                ablk_usage = addr_block['usage']
                # TODO: Protection
                print(f'    address block... size {hex(ablk_size)} offset {hex(ablk_offset)} usage {ablk_usage}')
            per_registers = peripheral['registers']['register']
            for register in per_registers:
                reg_name = register['name']
                reg_desc = register['description']
                reg_addr_offset = register['addressOffset']
                reg_size = register['size']
                reg_fields = register['fields']['field']
                print(f'    register... {hex(reg_addr_offset)} @ {reg_name} size {hex(reg_size)}')