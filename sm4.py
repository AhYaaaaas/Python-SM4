class SM4:

    def __init__(self, message, mk0, mk1, mk2, mk3, aim):
        self.message = message
        self.aim = aim
        self.s_box = [
            0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05, 0x2B,
            0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42,
            0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62, 0xE4, 0xB3, 0x1C,
            0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC,
            0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2, 0x71,
            0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35, 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58,
            0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27,
            0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
            0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1, 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD,
            0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29,
            0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A,
            0x72, 0x6D, 0x6C, 0x5B, 0x51, 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
            0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8,
            0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E,
            0xC6, 0x84, 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39,
            0x48
        ]
        self.CK = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        ]
        self.FK = [
            0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
        ]
        # 初始密钥
        self.init_mk_list = [mk0, mk1, mk2, mk3]
        self.k_list = []
        self.k_s_box = []
        self.rk = []
        self.initList = ['', '', '', '']

    """
        128bit ==>4x32bit
    """

    def group_by_32(self):
        self.initList[0] = self.message[0:32]
        self.initList[1] = self.message[32:64]
        self.initList[2] = self.message[64:96]
        self.initList[3] = self.message[96:128]

    """
        32bit==>4x8bit
    """

    def group_by_8(self, message):
        return [message[0:8], message[8:16], message[16:24], message[24:32]]

    def move(self, content, step):
        return content[step::] + content[0:step]

    """
        三十二位异或操作
    """

    def convert_to_s_box(self, message):
        num = int(message, 2)
        e1 = self.s_box[num]
        e1 = "{:08b}".format(e1)
        return e1

    def xor_32(self, str1, str2):
        s = ""
        str1 = str(str1)
        str2 = str(str2)
        for i in range(32):
            s += str(int(str1[i]) ^ int(str2[i]))
        return s

    def unline_function(self, message):  # message 是三十二位二进制数
        group_list_8 = self.group_by_8(message)
        blank_list = []
        for i in group_list_8:
            blank_list.append(self.convert_to_s_box(i))
        message = ''.join(blank_list)  # message经过S盒变换重新变回三十二位二进制数
        return message

    def line_function(self, message, flag):  # message是经过S盒非线性变换传入的  flag=0==>加密 flag=1==>密钥扩展
        if flag == 0:
            tmp_list = [message, self.move(message, 2), self.move(message, 10), self.move(message, 18),
                        self.move(message, 24)]
            part1 = self.xor_32(tmp_list[0], tmp_list[1])
            part2 = self.xor_32(tmp_list[2], part1)
            part3 = self.xor_32(tmp_list[3], part2)
            res2 = self.xor_32(tmp_list[4], part3)
        else:
            tmp_list = [message, self.move(message, 13), self.move(message, 23)]
            res2 = self.xor_32(self.xor_32(tmp_list[0], tmp_list[1]), tmp_list[2])
        return res2

    def t(self, message, flag):  # message是三十二位二进制数
        message = self.unline_function(message)
        t_out = self.line_function(message, flag)
        return t_out  # 输出经过线性和非线性变换后的三十二位二进制数

    def lun_function(self, x0, x1, x2, x3, rk, flag):  # 传入参数均是三十二位二进制数
        result = self.xor_32(x1, x2)
        result = self.xor_32(result, x3)
        result = self.xor_32(result, rk)
        result = self.t(result, flag)
        result = self.xor_32(result, x0)
        return result

    """
        密钥扩展
    """

    def extend_mk(self):
        for j in range(len(self.CK)):
            self.CK[j] = "{:032b}".format(self.CK[j])
        for k in range(4):
            # 获得k0-k3,以及对应S盒内容
            self.k_list.append(self.xor_32(self.init_mk_list[k], "{:032b}".format(self.FK[k])))

        for p in range(32):
            part2 = self.lun_function(self.k_list[p], self.k_list[p + 1], self.k_list[p + 2], self.k_list[p + 3],
                                      self.CK[p], 1)
            self.k_list.append(part2)
            self.rk.append(part2)
        if self.aim == 1:
            self.rk.reverse()

    def encrypt_or_decrypt(self):
        self.group_by_32()
        self.extend_mk()
        # 四组初始数据
        x0 = self.initList[0]
        x1 = self.initList[1]
        x2 = self.initList[2]
        x3 = self.initList[3]
        x_list = [x0, x1, x2, x3]
        for i in range(32):
            x_list.append(self.lun_function(x_list[i], x_list[i + 1], x_list[i + 2], x_list[i + 3], self.rk[i], 0))
        result = [x_list[35], x_list[34], x_list[33], x_list[32]]
        return result


# 16进制
def handle_input_data(content):
    example_list = []
    for i in content:
        example_list.append("{:04b}".format(eval("0x" + i)))
    return ''.join(example_list)


def handle_output_data(content):
    res = []
    for i in content:
        temp = "{:08x}".format(eval("0b" + i))
        res.append(temp[0:4])
        res.append(temp[4:8])
    return res


if __name__ == '__main__':
    mk0 = handle_input_data('12325678')
    mk1 = handle_input_data('1234abcd')
    mk2 = handle_input_data('87654321')
    mk3 = handle_input_data('dcba4321')
    message = "我喜欢上《网络空间安全理论与技术（乙）》课，我愿意接受这1次challenge！"
    a = ["{:04x}".format(ord(i)) for i in message]
    res = []
    for index in range(0, len(a) - 1, 8):
        round_message = handle_input_data(''.join(a[index:index + 8]))
        s = SM4(round_message, mk0, mk1, mk2, mk3, 0)
        res += handle_output_data(s.encrypt_or_decrypt())
    print(res)
    initial = []
    for index in range(0, len(a) - 1, 8):
        round_message = handle_input_data(''.join(res[index:index + 8]))
        s = SM4(round_message, mk0, mk1, mk2, mk3, 1)
        initial += handle_output_data(s.encrypt_or_decrypt())
    print(initial)
    print(''.join([chr(int('0x' + char, 16)) for char in initial]))
