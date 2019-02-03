use tonlabs_sdk_emulator::bitstring::Bitstring;
use tonlabs_sdk_emulator::stack::BuilderData;

pub fn prepend_reference(builder: &mut BuilderData, child: BuilderData) {
    builder.update_cell(
        |_, children, child| {
            children.insert(0, child);
        },
        child,
    );
}

// shifts existing cell data and put provided data at the beginning
pub fn prepend_data(builder: &mut BuilderData, data: &Bitstring) {
    builder.update_cell(
        |cell_data, _, data| {
            let mut buffer = data.clone();
            buffer.append(&Bitstring::from_bitstring_with_completion_tag(
                cell_data.clone(),
            ));
            cell_data.clear();
            buffer.into_bitstring_with_completion_tag(cell_data);
        },
        data,
    );
}

// put data to cell and make chain if data doesn't fit into cell
pub fn prepend_data_to_chain(mut builder: BuilderData, data: Bitstring) -> BuilderData {
    let mut data = data;

    while data.length_in_bits() > 0 {
        let remaining_bits = builder.bits_capacity() - builder.bits_used();

        if remaining_bits > 0 {
            // data does not fit into cell - fill current cell and take remaining data
            if remaining_bits < data.length_in_bits() {
                let mut cut = Bitstring::new();
                // TODO: replace iteration on Bits with Bitstring::substring function
                data.bits(data.length_in_bits() - remaining_bits..data.length_in_bits())
                    .data
                    .iter()
                    .for_each(|x| {
                        cut.append_bit(x);
                    });
                prepend_data(&mut builder, &cut);

                cut.clear();
                data.bits(0..data.length_in_bits() - remaining_bits)
                    .data
                    .iter()
                    .for_each(|x| {
                        cut.append_bit(x);
                    });

                data = cut;
            } else {
                // data fit into current cell - no data remaining
                prepend_data(&mut builder, &data);

                data.clear();
            }
        } else {
            // current cell is full - move to next
            let mut next_builder = BuilderData::new();
            next_builder.append_reference(builder);
            builder = next_builder;
        }
    }

    builder
}