// Pattern for binary logging files (Vector BLF)
// References used for writing this:
// https://python-can.readthedocs.io/en/stable/_modules/can/io/blf.html
// https://bitbucket.org/tobylorenz/vector_blf

#pragma magic [ 4C 4F 47 47 ] @ 0x00
#pragma array_limit 4194304
#pragma pattern_limit 4294967296
#pragma endian little

import hex.dec;
import std.io;
import type.magic;

enum object_type : u32 {
    unknown = 0,
    can_message = 1,
    can_error = 2,
    can_overload = 3,
    can_statistic = 4,
    log_container = 10,
    app_text = 0x41, // 65
    can_message2 = 0x56, // 86
    can_fd_message = 100,
    can_fd_message_64 = 101,
    can_fd_error_64 = 104,
    rpc_unknown = 115, // ? "RestorePointContainer"
};

struct can_msg {
    u16 channel;
    u8 flags;
    u8 dlc;
    u32 id;
    u8 data[8];
};
struct can_msg2 {
    u16 channel;
    u8 flags;
    u8 dlc;
    u32 id;

    auto struct_len = 2 + 1 + 1 + 4 + 4 + 1 + 1 + 2; // TODO: Alternative way of doing this?
    u8 data[parent.header.object_size - parent.header.header_size - struct_len];

    u32 frame_length;
    u8 bit_count;
    padding[1];
    padding[2];
};
struct can_fd_msg {
    u16 channel;
    u8 flags;
    u8 dlc;
    u32 id;
    u32 frame_len;
    u8 arbitration_bit_count;
    u8 fd_flags;
    u8 valid_data_bytes;
    padding[1];
    padding[4];

    u8 data[64];

    padding[4];
};

struct app_text {
    u32 source;
    padding[4];
    u32 text_length;
    padding[4];
    char text[text_length];
};

/// No idea what this is, apparently called "RestorePointContainer"
struct rpc_container {
    u8 rpc[14];
    u16 data_len;
    u8 data[data_len];
};

enum compression_method : u16 {
    no_compression = 0,
    zlib = 2,
};

// The following section contains all of the decompressed data at once
std::mem::Section decompressed_data = std::mem::create_section("Decompressed data");
// This section is used only for decompressing data
std::mem::Section zlib_decompress_result = std::mem::create_section("zlib decompress result");

struct log_container {
    u64 container_begin = $;

    compression_method compression_method;
    padding[2];
    padding[4];
    u32 uncompressed_size;
    padding[4];

    if (compression_method == compression_method::zlib) {
        std::mem::set_section_size(zlib_decompress_result, uncompressed_size);

        // Create a pattern that defines the compressed array data
        auto compressed_byte_len = parent.header.object_size - parent.header.header_size - ($ - container_begin);
        u8 compressed[compressed_byte_len];
        if (uncompressed_size != 0)
            padding[parent.header.object_size % 4]; // Idk, the format wants this... for some reason

        std::assert(hex::dec::zlib_decompress(compressed, zlib_decompress_result) == compressed_byte_len,
            "zlib decompress needs to succeed");

        // Copy the decompressed data to the end of the section
        std::mem::copy_section_to_section(zlib_decompress_result, 0,
            decompressed_data, std::mem::get_section_size(decompressed_data),
            std::mem::get_section_size(zlib_decompress_result));
    } else if (compression_method == compression_method::no_compression) {
        u8 data[uncompressed_size];
        std::mem::copy_value_to_section(data, decompressed_data, std::mem::get_section_size(decompressed_data));
    } else {
        std::assert(false, "Invalid/unknown compression method");
    }
};

enum object_flags : u32 {
    time_10_ms = 1,
    time_1_ns = 2,
};

enum timestamp_status : u8 {
    orig = 0x01,
    swhw = 0x02,
    user = 0x10,
};

struct obj_v1_header {
    object_flags flags;
    u16 client_index;
    u16 object_version;
    u64 timestamp;
};
struct obj_v2_header {
    object_flags flags;
    timestamp_status timestamp_status;
    u8 padding0;
    u16 object_version;
    u64 timestamp;
    u8 padding1[8];
};

struct obj_header {
    type::Magic<"LOBJ"> magic; // 4C 4F 42 4A
    u16 header_size;
    u16 header_version;
    u32 object_size;
    object_type object_type;

    std::assert(header_version == 1 || header_version == 2, "Invalid/unknown header version");
};

struct obj_struct {
    obj_header header [[inline]];

    if (header.object_type == object_type::log_container) {
        log_container log [[inline]];
    } else {
        if (header.header_version == 1)
            obj_v1_header v1_header [[inline]];
        else if (header.header_version == 2)
            obj_v2_header v2_header [[inline]];

        match(header.object_type) {
            (object_type::can_message): {
                can_msg message [[inline]];
            }
            (object_type::can_message2): {
                can_msg2 message [[inline]];
            }
            (object_type::can_fd_message): {
                can_fd_msg message [[inline]];
            }
            (object_type::app_text): {
                app_text text [[inline]];
                padding[header.object_size % 4];
            }
            (object_type::rpc_unknown): {
                rpc_container rpc [[inline]];
            }
            (_): u8 bytes[header.object_size - header.header_size];
        }
    }
};

enum application_id : u8 {
    unknown = 0,
    canalyzer = 1,
    canoe = 2,
    canstress = 3,
    canlog = 4,
    canape = 5,
    cancasexl = 6,
    vlconfig = 7,
    porsche_logger = 200,
    caetec_logger = 201,
    vector_net_sim = 202,
    ipetronik_logger = 203,
    rtpk = 204,
    piketec = 205,
    sparks = 206,
};

fn format_api_version(u32 api_version) {
    return std::format("{}.{}.{}",
        api_version / 1000000,
        (api_version % 1000000) / 1000,
        (api_version % 1000) / 100);
};

// Mostly just the zlib compression levels, but with some extras
enum compression_level : u8 {
    no_compression = 0,
    best_speed = 1,
    default_compression = 6,
    best_compression = 9,
    // This means that the file contains only log containers, usually compressed at level 6
    default_container_compression = 10,
};

fn extract_u16(u64 data, u64 idx) {
    return u16((data >> idx * 16) & 0xFFFF);
};
fn format_timestamp(u128 start_timestamp) {
    u64 date = u64(start_timestamp);
    u64 time = u64(start_timestamp >> 64);
    return std::format("{}-{}-{}_{}-{}-{}",
        extract_u16(date, 0), extract_u16(date, 1), extract_u16(date, 3),
        extract_u16(time, 0), extract_u16(time, 1), extract_u16(time, 2));
};

struct file_header {
    type::Magic<"LOGG"> magic; // 4C 4F 47 47
    u32 header_length;

    u32 api_version [[format("format_api_version")]];
    application_id app_id;
    compression_level compression_level;
    u8 app_major;
    u8 app_minor;

    u64 file_length;
    u64 uncompressed_length;
    u32 object_count;
    u32 application_build;

    u128 start_timestamp [[format("format_timestamp")]];
    u128 stop_timestamp [[format("format_timestamp")]];

    u64 restore_point_offset; // ?
} [[inline]];

struct file_layout {
    file_header header;
    padding[header.header_length - sizeof(header)];
    obj_struct objects[while($ < std::mem::size())];

    // Decode all objects from the zlib compressed data
    if (std::mem::get_section_size(decompressed_data) != 0)
        obj_struct decompressed_objects[header.object_count] @ 0x00 in decompressed_data;
} [[inline]];

file_layout file @ 0x00;

std::assert_warn(std::mem::size() == file.header.file_length, "file size mismatch");
