#!/bin/env python3

import re
import argparse
import sys
import os

class Utils:
    """
    Utility class. Contains script utilities, mostly used for bitwise
    manipulation
    """

    def get_bit_offsets(val):
        """
        Returns array with shifts of all the
        bits set in value
        @param val: value to get bits from
        """
        set_bits = []
        idx = 0
        while val != 0:
            if val & 0x1:
                set_bits.append(idx)
            idx += 1
            val = val >> 1
        return set_bits

    def count_set_bits(val):
        """
        Counts number of bits set in value
        @param val: value to count bits in
        """
        return len(Utils.get_bit_offsets(val))

    def get_bit_shift(val):
        """
        Gets bit shift of a value
        @param val: value to get bit shift for
        """
        if val == 0:
            return 0
        bit_offsets = Utils.get_bit_offsets(val)
        return min(bit_offsets)

    def count_bit_width(val):
        """
        Counts bit width of mask. For example,
        bit width of 0xF010 would be 12 (12 bits needed to store it with
        shift)
        @param val: value to calculate bit width for
        """
        bit_offsets = Utils.get_bit_offsets(val)
        return max(bit_offsets) - min(bit_offsets) + 1


class SDKIOMUX_Option:
    """
    SDK IOMUX option class. Represents SDK IOMUX pin option.
    """
    # Regex expression to parse an macro like the following:
    #define IO_MUX_SGPIO29                                                                   \
    # 0x00000000U, 0x20000000U,                                       /* Pin mask */         \
    #     IO_MUX_GPIO_FC_MASK(2, 0, 0x0EC), IO_MUX_GPIO_FC_MASK(1, 0, 0), /* GPIO&FC mask */ \
    #     0x00000000U, 0x20000000U,                                   /* FSEL mask */        \
    #     IO_MUX_CTIMER_MASK(0, 0), IO_MUX_CTIMER_MASK(0, 0),         /* CTimer mask */      \
    #     IO_MUX_SCTIMER_MASK(0, 0), IO_MUX_SCTIMER_MASK(0, 0)        /* SCTimer mask */
    iomux_regex = re.compile(r'#define (IO_MUX_\w+).*\n' # Matches first line
        r'\s+(0x[\dA-F]+)U, (0x[\dA-F]+)U,\s+.*\n' # Matches second line
        r'\s+IO_MUX_GPIO_FC_MASK\((\d), ([\dxA-F]+), ([\dxA-F]+)\), ' # Matches first GPIO_FC macro (third line)
        r'IO_MUX_GPIO_FC_MASK\((\d), ([\dxA-F]+), ([\dxA-F]+)\),.*\n' # Matches second GPIO_FC macro (third line)
        r'\s+(0x[\dA-F]+)U, (0x[\dA-F]+)U,.*\n' # Matches fourth line
        r'\s+IO_MUX_CTIMER_MASK\(([\dxA-F]+), ([\dxA-F]+)\), ' # Matches first CTIMER macro (fifth line)
        r'IO_MUX_CTIMER_MASK\(([\dxA-F]+), ([\dxA-F]+)\),.*\n' # Matches second CTIMER macro (fifth line)
        r'\s+IO_MUX_SCTIMER_MASK\(([\dxA-F]+), ([\dxA-F]+)\), ' # Matches first SCTIMER macro (sixth line)
        r'IO_MUX_SCTIMER_MASK\(([\dxA-F]+), ([\dxA-F]+)\)') # Matches second SCTIMER macro (sixth line)

    def from_str(mux_str):
        """
        Creates mux options from a string, by matching all possible
        mux options in the string data
        @param mux_str: string to use to create mux options. May include
            invalid mux option data, as regex match will skip this.
            For example, this regex can be used to match against the
            contents of the driver file.
        """
        # Find all options in string, breaking into array of
        # tuples (each tuple contains all group members for that match)
        matches = SDKIOMUX_Option.iomux_regex.findall(mux_str)
        opts = []
        for match in matches:
            # First match is name, don't convert that to integer
            args = [match[0]]
            for string in match[1:]:
                # Convert remaining matches to integers
                args.append(int(string, 0))
            opts.append(SDKIOMUX_Option(*args))
        return opts


    def __init__(self, name, gpl_mask, gph_mask, gp_set_flags, fc_set_idx,
            fc_set_mask, gp_clr_flags, fc_clr_idx, fc_clr_mask,
            fsel_set_mask, fsel_clr_mask, ctim_set_in_mask,
            ctim_set_out_mask, ctim_clr_in_mask, ctim_clr_out_mask,
            sctim_set_in_mask, sctim_set_out_mask, sctim_clr_in_mask,
            sctim_clr_out_mask):
        """
        Initializes SDK MUX.
        takes the following arguments:
        @param name: name of mux option
        @param gpl_mask: GPIO low pin mask
        @param gph_mask: GPIO high pin mask
        @param gp_set_flags: GPIO set flags
        @param fc_set_idx: flexcomm set IDX
        @param fc_set_mask: flexcomm set mask
        @param gp_clr_flags: GPIO clear flags
        @param fc_clr_idx: flexcomm clear IDX
        @param fc_clr_mask: flexcomm clear mask
        @param fsel_set_mask: FSEL set mask
        @param fsel_clr_mask: FSEL clear mask
        @param ctim_set_in_mask: ctimer in set mask
        @param ctim_set_out_mask: ctimer out set mask
        @param ctim_clr_in_mask: ctimer in clear mask
        @param ctim_clr_out_mask: ctimer out clear mask
        @param sctim_set_in_mask: sctimer in set mask
        @param sctim_set_out_mask: sctimer out set mask
        @param sctim_clr_in_mask: sctimer in clear mask
        @param sctim_clr_out_mask: sctimer out clear mask
        """
        self.name = name
        self._type = "unset"
        # Perform validation of MUX options
        if gp_set_flags != 0:
            # Verify that no other peripherals are being enabled
            if fc_set_mask != 0:
                raise RuntimeError(f"MUX option {name} sets gpio and flexcomm")
            if fsel_set_mask != 0:
                raise RuntimeError(f"MUX option {name} sets gpio and fsel")
            if ctim_set_in_mask != 0:
                raise RuntimeError(f"MUX option {name} sets gpio and ctim_in")
            if ctim_set_out_mask != 0:
                raise RuntimeError(f"MUX option {name} sets gpio and ctim_out")
            if sctim_set_in_mask != 0:
                raise RuntimeError(f"MUX option {name} sets gpio and sctim_in")
            if sctim_set_out_mask != 0:
                raise RuntimeError(f"MUX option {name} sets gpio and sctim_out")

        num_fc_bits = Utils.count_set_bits(fc_set_mask)
        if num_fc_bits > 1:
            raise RuntimeError(f"MUX option {self.name} sets multiple flexcomm bits: {num_fc_bits}")

        num_fsel_bits = Utils.count_set_bits(fsel_set_mask)
        if num_fsel_bits > 1:
            raise RuntimeError(f"MUX option {self.name} sets multiple fsel bits: {num_fsel_bits}")

        if fc_set_idx != fc_clr_idx:
            if (fc_set_mask != 0) and (fc_clr_mask != 0):
                raise RuntimeError(f"MUX option {name} configures multiple flexcomm")
        # Validation complete. Parse mux option
        if gp_set_flags != 0:
            # This is a gpio mux option.
            if gp_set_flags == 2:
                self._type = "IOMUX_SGPIO"
            elif gp_set_flags == 1:
                self._type = "IOMUX_GPIO"
            else:
                raise RuntimeError(f"MUX option {name} has invalid gp_set_flags")
            # Pull out all the peripheral selection clear flags
            self._fc_clr_idx = fc_clr_idx
            self._fc_clr_mask = fc_clr_mask
            self._fsel_clr_mask = fsel_clr_mask
            if ctim_clr_in_mask != ctim_clr_out_mask:
                raise RuntimeError(f"MUX option {name} has invalid ctim_clr flags")
            self._ctimer_mask = ctim_clr_in_mask
            self._sctimer_in_mask = sctim_clr_out_mask
            self._sctimer_out_mask = sctim_clr_out_mask
            # Get GPIO index
            gpio_count = (Utils.count_set_bits(gpl_mask) +
                Utils.count_set_bits(gph_mask))
            if gpio_count == 0:
                raise RuntimeError(f"GPIO MUX option {name} does not set any gpio")
            elif gpio_count != 1:
                raise RuntimeError(f"GPIO MUX option {name} sets multiple gpio")
            if gpl_mask != 0:
                self._gpios = [Utils.get_bit_shift(gpl_mask)]
            elif gph_mask != 0:
                self._gpios = [Utils.get_bit_shift(gph_mask) + 32]
        else:
            # Not a gpio mux option, determine the type
            # Multiple GPIOs may be set for this option, record them all
            self._gpios = Utils.get_bit_offsets(gpl_mask)
            self._gpios.extend(Utils.get_bit_offsets(gph_mask << 32))
            if fc_set_mask != 0:
                if self._type != "unset":
                    raise RuntimeError(f"MUX option {name} has ambiguous type")
                self._type = "IOMUX_FLEXCOMM"
                self._fc_set_idx = fc_set_idx
                self._fc_set_mask = fc_set_mask
            if fsel_set_mask != 0:
                if self._type != "unset":
                    raise RuntimeError(f"MUX option {name} has ambiguous type")
                self._type = "IOMUX_FSEL"
                self._fsel_mask = fsel_set_mask
            if ctim_set_in_mask != 0:
                if self._type != "unset":
                    raise RuntimeError(f"MUX option {name} has ambiguous type")
                self._type = "IOMUX_CTIMER_IN"
                self._ctimer_set_mask = ctim_set_in_mask
            if ctim_set_out_mask != 0:
                if self._type != "unset":
                    raise RuntimeError(f"MUX option {name} has ambiguous type")
                self._type = "IOMUX_CTIMER_OUT"
                self._ctimer_set_mask = ctim_set_out_mask
            if sctim_set_in_mask != 0:
                if self._type != "unset":
                    raise RuntimeError(f"MUX option {name} has ambiguous type")
                self._type = "IOMUX_SCTIMER_IN"
                self._sctimer_set_mask = sctim_set_in_mask
            if sctim_set_out_mask != 0:
                if self._type != "unset":
                    raise RuntimeError(f"MUX option {name} has ambiguous type")
                self._type = "IOMUX_SCTIMER_OUT"
                self._sctimer_set_mask = sctim_set_out_mask
            if self._type == "unset":
                # AON type sets no mux selection bits, only clears them
                self._type = "IOMUX_AON"

    def get_mux_options(self):
        """
        Gets all mux options. These mux options are given as induvidual
        pins, so multiple mux options may be returned. Returns a
        dict, where keys are mux option names and values are C macros
        """
        if self._type == "IOMUX_GPIO" or self._type == "IOMUX_SGPIO":
            # Return one available mux option
            macro = f"(IOMUX_GPIO_IDX({self._gpios[0]}) | IOMUX_TYPE({self._type}))\n"
            return {self.name: macro}
        else:
            macro_map = {}
            # Multiple mux options may exist, so iterate through all GPIOs
            for gpio in self._gpios:
                macro = (f"(IOMUX_GPIO_IDX({gpio}) | "
                    f"IOMUX_TYPE({self._type}) | \\\n\t")
                if self._type == "IOMUX_FLEXCOMM":
                    fc_bit_offset = Utils.get_bit_shift(self._fc_set_mask)
                    macro += (f"IOMUX_FLEXCOMM_IDX({self._fc_set_idx}) | "
                        f"IOMUX_FLEXCOMM_BIT({fc_bit_offset}))\n")
                    macro_map[self.name + f"_IO{gpio}"] = macro
                elif self._type == "IOMUX_FSEL":
                    fsel_bit_offset = Utils.get_bit_shift(self._fsel_mask)
                    macro += (f"IOMUX_FSEL_BIT({fsel_bit_offset}))\n")
                    macro_map[self.name + f"_IO{gpio}"] = macro
                elif self._type == "IOMUX_CTIMER_OUT" or self._type == "IOMUX_CTIMER_IN":
                    ctimer_bit_offset = Utils.get_bit_shift(self._ctimer_set_mask)
                    macro += f"IOMUX_CTIMER_BIT({ctimer_bit_offset}))\n"
                    macro_map[self.name + f"_IO{gpio}"] = macro
                elif self._type == "IOMUX_SCTIMER_OUT" or self._type == "IOMUX_SCTIMER_IN":
                    sctimer_bit_offset = Utils.get_bit_shift(self._sctimer_set_mask)
                    macro += f"IOMUX_CTIMER_BIT({sctimer_bit_offset}))\n"
                    macro_map[self.name + f"_IO{gpio}"] = macro
                elif self._type == "IOMUX_AON":
                    # No bits should be set for IOMUX_AON
                    macro = (f"(IOMUX_GPIO_IDX({gpio}) | "
                        f"IOMUX_TYPE({self._type}))\n")
                    macro_map[self.name + f"_IO{gpio}"] = macro
                else:
                    print(f"Warning: mux {self.name} has unhandled type {self._type}")
            return macro_map

    def get_gpio_option(self):
        """
        Gets GPIO mux option definition. GPIO mux option definitions will
        be defined as a set of registers to clear, to disable
        alternate functions.
        """
        if self._type == "IOMUX_GPIO" or self._type == "IOMUX_SGPIO":
            # Check if ctimer and sctimer bits need to be cleared
            if self._ctimer_mask:
                ctim_en = 1
                ctim_shift = Utils.get_bit_shift(self._ctimer_mask)
            else:
                ctim_en = 0
                ctim_shift = 0

            if self._sctimer_in_mask:
                sctim_in_en = 1
                sctim_in_shift = Utils.get_bit_shift(self._sctimer_in_mask)
            else:
                sctim_in_en = 0
                sctim_in_shift = 0

            if self._sctimer_out_mask:
                sctim_out_en = 1
                sctim_out_shift = Utils.get_bit_shift(self._sctimer_out_mask)
            else:
                sctim_out_en = 0
                sctim_out_shift = 0
            # Set output
            return (f"(IOMUX_FLEXCOMM_CLR(0x{self._fc_clr_idx:x}ULL, 0x{self._fc_clr_mask:x}ULL) | "
                "/* Flexcomm bits to clear */ \\\n"
                f"\tIOMUX_FSEL_CLR(0x{self._fsel_clr_mask:x}ULL) | /* FSEL bits to clear */ \\\n"
                f"\tIOMUX_CTIMER_CLR({ctim_shift}ULL, {ctim_en}ULL) | /* CTIMER offset to clear */ \\\n"
                f"\tIOMUX_SCTIMER_IN_CLR({sctim_in_shift}ULL, {sctim_in_en}ULL) | "
                "/* SCTIMER input offset to clear */ \\\n"
                f"\tIOMUX_SCTIMER_OUT_CLR({sctim_out_shift}ULL, {sctim_out_en}ULL)) "
                "/* SCTIMER output offset to clear */\n")
        else:
            return ""

    def is_gpio(self):
        """
        Returns true if option is a GPIO mux option
        """
        return self._type == "IOMUX_GPIO"

    def get_gpio_pin(self):
        """
        Gets GPIO pin index for GPIO mux options
        """
        if not self.is_gpio():
            return 0
        return self._gpios[0]

    def __repr__(self):
        """
        Print a debug representation of the object
        """
        return f"SDKIOMUX_Option({self._type})"


def parse_args():
    """
    Parses program arguments
    """
    parser = argparse.ArgumentParser(
                description="Process RW61x fsl_io_mux.h driver")
    parser.add_argument("io_mux_file", metavar="FILE", type=str,
                        help="fsl_io_mux.h file to parse")
    parser.add_argument("--output", metavar="OUT", type=str,
                        help="output file for IOMUX definitions")
    return parser.parse_args()


def parse_iomux(iomux_file):
    """
    Parses SDK iomux driver file for RW61x, reading each SDK iomux
    """
    mux_options = []
    with open(iomux_file, 'r') as iomux_stream:
        # Read lines from iomux driver until we reach EOF
        iomux_data = iomux_stream.read()
        mux_options = SDKIOMUX_Option.from_str(iomux_data)
    return mux_options

def write_iomux(outfile, mux_data):
    """
    Writes pin control output data to output file
    """
    if outfile:
        ostream = open(outfile, 'w')
    else:
        ostream = sys.stdout

    # This is a hack- but there is no identifying data for the RW610 vs RW612
    # in their IOMUX header files. Just use the file name to determine which
    # soc we are (probably) targeting :(
    if "RW610" in outfile:
        soc = "RW610"
    else:
        soc = "RW612"

    # Write header
    ostream.write("/*\n"
            f" * Note: File generated by {os.path.basename(__file__)}\n"
            f" * for {soc}\n"
            " */\n\n")


    ostream.write(f"#ifndef _ZEPHYR_DTS_BINDING_{soc}_\n"
        f"#define _ZEPHYR_DTS_BINDING_{soc}_\n\n")

    # Write all required macro definitions
    ostream.write(
        "/* Internal macros to pack and extract pin configuration data. */\n"
        "/* GPIO configuration packing macros */\n"
        "#define IOMUX_OFFSET_ENABLE(offset, enable, shift) \\\n"
        "\t((((offset) << 1) | (enable & 0x1)) << shift)\n"
        "#define IOMUX_SCTIMER_OUT_CLR(offset, enable) \\\n"
        "\tIOMUX_OFFSET_ENABLE(offset, enable, 0)\n"
        "#define IOMUX_SCTIMER_IN_CLR(offset, enable) \\\n"
        "\tIOMUX_OFFSET_ENABLE(offset, enable, 4)\n"
        "#define IOMUX_CTIMER_CLR(offset, enable)\\\n"
        "\tIOMUX_OFFSET_ENABLE(offset, enable, 8)\n"
        "#define IOMUX_FSEL_CLR(mask) ((mask) << 13)\n"
        "#define IOMUX_FLEXCOMM_CLR(idx, mask) \\\n"
        "\t(((mask) << 45) | ((idx) << 56))\n\n"
        "/* GPIO configuration extraction macros */\n"
        "#define IOMUX_GET_SCTIMER_OUT_CLR_ENABLE(mux) ((mux) & 0x1)\n"
        "#define IOMUX_GET_SCTIMER_OUT_CLR_OFFSET(mux) (((mux) >> 1) & 0x7)\n"
        "#define IOMUX_GET_SCTIMER_IN_CLR_ENABLE(mux) (((mux) >> 4) & 0x1)\n"
        "#define IOMUX_GET_SCTIMER_IN_CLR_OFFSET(mux) (((mux) >> 5) & 0x7)\n"
        "#define IOMUX_GET_CTIMER_CLR_ENABLE(mux) (((mux) >> 8) & 0x1ULL)\n"
        "#define IOMUX_GET_CTIMER_CLR_OFFSET(mux) (((mux) >> 9) & 0xFULL)\n"
        "#define IOMUX_GET_FSEL_CLR_MASK(mux) (((mux) >> 13) & 0xFFFFFFFFULL)\n"
        "#define IOMUX_GET_FLEXCOMM_CLR_MASK(mux) \\\n"
        "\t(((mux) >> 45) & 0x7FFULL)\n"
        "#define IOMUX_GET_FLEXCOMM_CLR_IDX(mux) \\\n"
        "\t(((mux) >> 56) & 0xF)\n\n"
        "/* Pin mux type and gpio offset macros */\n"
        "#define IOMUX_GPIO_IDX(x) ((x) & 0x7F)\n"
        "#define IOMUX_TYPE(x) (((x) & 0xF) << 7)\n"
        "#define IOMUX_GET_GPIO_IDX(mux) ((mux) & 0x7F)\n"
        "#define IOMUX_GET_TYPE(mux) (((mux) >> 7) & 0xF)\n\n"
        "/* Flexcomm specific macros */\n"
        "#define IOMUX_FLEXCOMM_IDX(x) (((x) & 0xF) << 11)\n"
        "#define IOMUX_FLEXCOMM_BIT(x) (((x) & 0xF) << 15)\n"
        "#define IOMUX_GET_FLEXCOMM_IDX(mux) (((mux) >> 11) & 0xF)\n"
        "#define IOMUX_GET_FLEXCOMM_BIT(mux) (((mux) >> 15) & 0xF)\n\n"
        "/* Function select specific macros */\n"
        "#define IOMUX_FSEL_BIT(mux) (((mux) & 0x1F) << 11)\n"
        "#define IOMUX_GET_FSEL_BIT(mux) (((mux) >> 11) & 0x1F)\n\n"
        "/* CTimer specific macros */\n"
        "#define IOMUX_CTIMER_BIT(x) (((x) & 0xF) << 11)\n"
        "#define IOMUX_GET_CTIMER_BIT(mux) (((mux) >> 11) & 0xF)\n\n"
        "/* SCtimer specific macros */\n"
        "#define IOMUX_SCTIMER_BIT(x) (((x) & 0xF) << 11)\n"
        "#define IOMUX_GET_SCTIMER_BIT(mux) (((mux) >> 11) & 0xF)\n\n\n"
        "/* Mux Types */\n"
        "#define IOMUX_FLEXCOMM 0x0\n"
        "#define IOMUX_FSEL 0x1\n"
        "#define IOMUX_CTIMER_IN 0x2\n"
        "#define IOMUX_CTIMER_OUT 0x3\n"
        "#define IOMUX_SCTIMER_IN 0x4\n"
        "#define IOMUX_SCTIMER_OUT 0x5\n"
        "#define IOMUX_GPIO 0x6\n"
        "#define IOMUX_SGPIO 0x7\n"
        "#define IOMUX_AON 0x8\n\n\n"
        "/* Pin configuration settings */\n"
        "#define IOMUX_PAD_PULL(x) (((x) & 0x3) << 19)\n"
        "#define IOMUX_PAD_SLEW(x) (((x) & 0x3) << 21)\n"
        "#define IOMUX_PAD_SLEEP_FORCE(en, val) \\\n"
        "\t((((en) & 0x1) << 24) | (((val) & 0x1) << 23))\n"
        "#define IOMUX_PAD_GET_PULL(mux) (((mux) >> 19) & 0x3)\n"
        "#define IOMUX_PAD_GET_SLEW(mux) (((mux) >> 21) & 0x3)\n"
        "#define IOMUX_PAD_GET_SLEEP_FORCE_EN(mux) (((mux) >> 24) & 0x1)\n"
        "#define IOMUX_PAD_GET_SLEEP_FORCE_VAL(mux) (((mux) >> 23) & 0x1)\n"
        )


    ostream.write("/*\n"
            " * GPIO mux options. These options are used to clear all alternate\n"
            " * pin functions, so the pin controller will use GPIO mode.\n"
            " */\n\n")

    gpio_defs = []
    for mux in mux_data:
        if mux.is_gpio():
            gpio_def = mux.get_gpio_option()
            name = f"IOMUX_GPIO_CLR_{mux.get_gpio_pin()}"
            ostream.write(f"#define {name} \\\n\t{gpio_def}\n")
            gpio_defs.append(name)


    gpio_ops = f"#define IOMUX_GPIO_OPS \\\n\t"
    for idx in range(len(gpio_defs)):
        gpio_ops += f"{gpio_defs[idx]}, "
        if (((idx + 1) % 4) == 0):
            gpio_ops += "\\\n\t"
    gpio_ops = re.sub(r', \\\n\t$', "\n\n", gpio_ops)
    ostream.write(gpio_ops)

    ostream.write("/*\n"
            " * Alternate mux functions. These functions select alternate\n"
            " * modes for pins\n"
            " */\n\n")
    for mux in mux_data:
        mux_defines = mux.get_mux_options()
        macros = []
        for (macro, val) in mux_defines.items():
            ostream.write(f"#define {macro} \\\n\t{val}\n")
            macros.append(macro)
        if not mux.is_gpio():
            ostream.write(f"#define {mux.name} {' '.join(macros)}\n\n")

    ostream.write(f"#endif /* _ZEPHYR_DTS_BINDING_{soc}_ */\n")

    if outfile:
        ostream.close()


if __name__ == "__main__":
    args = parse_args()
    mux_options = parse_iomux(args.io_mux_file)
    write_iomux(args.output, mux_options)
