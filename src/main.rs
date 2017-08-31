extern crate byteorder;
extern crate chrono;
extern crate getopts;
extern crate num;
#[macro_use] extern crate serde_derive;
extern crate serde_yaml;
extern crate time;

use std::io::prelude::*;
use std::cmp::PartialEq;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write, BufReader, Read};
use std::net::TcpStream;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use chrono::prelude::*;
use getopts::Options;
use num::{FromPrimitive, pow, ToPrimitive};
use time::Duration;


#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum DataType {
    Command = 0x2010,
    CommandReply = 0x2020,
    Error = 0x2030,
    ScanData = 0x2202,
    ObjectData = 0x2221,
    MovementData = 0x2805,
    EgoMotionData = 0x2850,
    SensorInfo = 0x7100,
}

impl FromPrimitive for DataType {
    fn from_i64(n: i64) -> Option<DataType> {
        match n {
            0x2010 => Some(DataType::Command),
            0x2020 => Some(DataType::CommandReply),
            0x2030 => Some(DataType::Error),
            0x2202 => Some(DataType::ScanData),
            0x2221 => Some(DataType::ObjectData),
            0x2805 => Some(DataType::MovementData),
            0x2850 => Some(DataType::EgoMotionData),
            0x7100 => Some(DataType::SensorInfo),
            _ => None,
        }
    }

    fn from_u64(n: u64) -> Option<DataType> {
        match n {
            0x2010 => Some(DataType::Command),
            0x2020 => Some(DataType::CommandReply),
            0x2030 => Some(DataType::Error),
            0x2202 => Some(DataType::ScanData),
            0x2221 => Some(DataType::ObjectData),
            0x2805 => Some(DataType::MovementData),
            0x2850 => Some(DataType::EgoMotionData),
            0x7100 => Some(DataType::SensorInfo),
            _ => None,
        }
    }
}

impl ToPrimitive for DataType {
    fn to_i64(self: &DataType) -> Option<i64> {
        match self {
                &DataType::Command => Some(0x2010),
                &DataType::CommandReply => Some(0x2020),
                &DataType::Error => Some(0x2030),
                &DataType::ScanData => Some(0x2202),
                &DataType::ObjectData => Some(0x2221),
                &DataType::MovementData => Some(0x2805),
                &DataType::EgoMotionData => Some(0x2850),
                &DataType::SensorInfo => Some(0x7100),
                _ => None,
        }
    }

    fn to_u64(self: &DataType) -> Option<u64> {
        match self {
                &DataType::Command => Some(0x2010),
                &DataType::CommandReply => Some(0x2020),
                &DataType::Error => Some(0x2030),
                &DataType::ScanData => Some(0x2202),
                &DataType::ObjectData => Some(0x2221),
                &DataType::MovementData => Some(0x2805),
                &DataType::EgoMotionData => Some(0x2850),
                &DataType::SensorInfo => Some(0x7100),
                _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Header {
    magic_word: u32,
    size_of_previous_messages: u32,
    size_of_message_data: u32,
    reserved: u8,
    device_id: u8,
    data_type: DataType,
    ntp_time: NtpTime,
}

impl Header {
    fn new(buffer: [u8; 24]) -> Header {
        Header {
            magic_word: BigEndian::read_u32(&buffer[0..4]),
            size_of_previous_messages: BigEndian::read_u32(&buffer[4..8]),
            size_of_message_data: BigEndian::read_u32(&buffer[8..12]),
            reserved: buffer[12],
            device_id: buffer[13],
            data_type: DataType::from_u16(BigEndian::read_u16(&buffer[14..16])).unwrap(),
            ntp_time: NtpTime {
                secs: BigEndian::read_u32(&buffer[16..20]),
                precise: BigEndian::read_u32(&buffer[20..24]),
            },
        }
    }

    fn print(&self) {
        println!("magic_word: {:x}", self.magic_word);
        println!("size_of_previous_messages: {}", self.size_of_previous_messages);
        println!("size_of_message_data: {}", self.size_of_message_data);
        println!("reserved: {:x}", self.reserved);
        println!("device_id: {}", self.device_id);
        match self.data_type {
            DataType::Command => println!("data_type: Command"),
            DataType::CommandReply => println!("data_type: CommandReply"),
            DataType::Error => println!("data_type: Error"),
            DataType::ScanData => println!("data_type: ScanData"),
            DataType::ObjectData => println!("data_type: ObjectData"),
            DataType::MovementData => println!("data_type: MovementData"),
            DataType::EgoMotionData => println!("data_type: EgoMotionData"),
            DataType::SensorInfo => println!("data_type: SensorInfo"),
            _ => {},
        }
        print!("ntp_time: ");
        self.ntp_time.print_datetime();
    }

    fn encode(&self, buffer: &mut [u8]) {
        BigEndian::write_u32(&mut buffer[0..4], self.magic_word);
        BigEndian::write_u32(&mut buffer[4..8], self.size_of_previous_messages);
        BigEndian::write_u32(&mut buffer[8..12], self.size_of_message_data);
        buffer[12] = self.reserved;
        buffer[13] = self.device_id;
        BigEndian::write_u16(&mut buffer[14..16], self.data_type.to_u64().unwrap() as u16);
        BigEndian::write_u32(&mut buffer[16..20], self.ntp_time.secs);
        BigEndian::write_u32(&mut buffer[20..24], self.ntp_time.precise);
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ScanData {
    scan_number: u16,
    scanner_status: u16,
    sync_phase_offset: u16,
    scan_start_time_ntp: NtpTime,
    scan_end_time_ntp: NtpTime,
    angle_ticks_per_rotation: u16,
    start_angle: i16,
    end_angle: i16,
    scan_points: u16,
    mounting_position_yaw_angle: i16,
    mounting_position_pitch_angle: i16,
    mounting_position_roll_angle: i16,
    mounting_position_x: i16,
    mounting_position_y: i16,
    mounting_position_z: i16,
    processing_flags: u16,
    scan_point_vec: Vec<ScanPoint>,
}

impl ScanData {
    fn new(buffer: &[u8]) -> ScanData {
        let mut scan_data = ScanData {
            scan_number: LittleEndian::read_u16(&buffer[0..2]),
            scanner_status: LittleEndian::read_u16(&buffer[2..4]),
            sync_phase_offset:LittleEndian::read_u16(&buffer[4..6]),
            scan_start_time_ntp: NtpTime {
                secs: LittleEndian::read_u32(&buffer[10..14]),
                precise: LittleEndian::read_u32(&buffer[6..10]),
            },
            scan_end_time_ntp: NtpTime {
                secs: LittleEndian::read_u32(&buffer[18..22]),
                precise: LittleEndian::read_u32(&buffer[14..18]),
            },
            angle_ticks_per_rotation: LittleEndian::read_u16(&buffer[22..24]),
            start_angle: LittleEndian::read_i16(&buffer[24..26]),
            end_angle: LittleEndian::read_i16(&buffer[26..28]),
            scan_points: LittleEndian::read_u16(&buffer[28..30]),
            mounting_position_yaw_angle: LittleEndian::read_i16(&buffer[30..32]),
            mounting_position_pitch_angle: LittleEndian::read_i16(&buffer[32..34]),
            mounting_position_roll_angle: LittleEndian::read_i16(&buffer[34..36]),
            mounting_position_x: LittleEndian::read_i16(&buffer[36..38]),
            mounting_position_y: LittleEndian::read_i16(&buffer[38..40]),
            mounting_position_z: LittleEndian::read_i16(&buffer[40..42]),
            processing_flags: LittleEndian::read_u16(&buffer[42..44]),
            scan_point_vec: Vec::new(),
        };
        let mut offset: usize = 44;
        let data_len: usize = 10;
        for i in 0..(scan_data.scan_points as usize) {
            scan_data.scan_point_vec.push(ScanPoint::new(&buffer[offset..offset+data_len]));
            offset = offset + data_len;
        }
        scan_data
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ScanPoint {
    layer_and_echo: u8,
    flags: u8,
    horizontal_angle: i16,
    radical_distance: u16,
    echo_pulse_width: u16,
    reserved: u16,
}

impl ScanPoint {
    fn new(buffer: &[u8]) -> ScanPoint {
        ScanPoint {
            layer_and_echo: buffer[0],
            flags: buffer[1],
            horizontal_angle: LittleEndian::read_i16(&buffer[2..4]),
            radical_distance: LittleEndian::read_u16(&buffer[4..6]),
            echo_pulse_width: LittleEndian::read_u16(&buffer[6..8]),
            reserved: LittleEndian::read_u16(&buffer[8..10]),
        }
    }

    fn print(&self) {
        println!("");
    }
}

// ntp_time
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ObjectData {
    scan_start_timestamp: NtpTime,
    number_of_objects: u16,
    objects_vec: Vec<ObjectInfo>,
}

impl ObjectData {
    fn new(buffer: &[u8]) -> ObjectData {
        let mut object_data = ObjectData {
            scan_start_timestamp: NtpTime {
                secs: LittleEndian::read_u32(&buffer[4..8]),
                precise: LittleEndian::read_u32(&buffer[0..4]),
            },
            number_of_objects: LittleEndian::read_u16(&buffer[8..10]),
            objects_vec: Vec::new(),
        };
        let mut number_of_contour_points: u16 = 0;
        let mut offset: usize = 10;
        let mut data_len: usize = 0;
        for i in 0..(object_data.number_of_objects as usize) {
            number_of_contour_points = LittleEndian::read_u16(&buffer[offset+56..offset+58]);
            data_len = 58 + (number_of_contour_points as usize) * 4;
            object_data.objects_vec.push(ObjectInfo::new(&buffer[offset..offset+data_len]));
            offset = offset + data_len;
        }
        object_data
    }

    fn print(&self) {
        print!("scan_start_timestamp: ");
        self.scan_start_timestamp.print();
        println!("number_of_object: {}", self.number_of_objects);
        for i in 0..self.objects_vec.len() {
            println!("object{}:", i);
            self.objects_vec[i].print()
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ObjectInfo {
    object_id: u16,
    object_age: u16,
    object_prediction_age: u16,
    relative_timestamp: u16,
    reference_point: Point2D,
    reference_point_sigma: Point2D,
    closest_point: Point2D,
    bounding_box_center: Point2D,
    bounding_box_size: Size2D,
    object_box_center: Point2D,
    object_box_size: Size2D,
    object_box_orientation: i16,
    absolute_velocity: Point2D,
    absolute_velocity_sigma: Size2D,
    relative_velocity: Point2D,
    reserved1: u16,
    reserved2: u16,
    reserved3: u16,
    number_of_contour_points: u16,
    contour_point_vec: Vec<Point2D>,
}

impl ObjectInfo {
    fn new(buffer: &[u8]) -> ObjectInfo {
        let mut object_info = ObjectInfo {
            object_id: LittleEndian::read_u16(&buffer[0..2]),
            object_age: LittleEndian::read_u16(&buffer[2..4]),
            object_prediction_age: LittleEndian::read_u16(&buffer[4..6]),
            relative_timestamp: LittleEndian::read_u16(&buffer[6..8]),
            reference_point: Point2D {
                position_x: LittleEndian::read_i16(&buffer[8..10]),
                position_y: LittleEndian::read_i16(&buffer[10..12]),
            },
            reference_point_sigma: Point2D {
                position_x: LittleEndian::read_i16(&buffer[12..14]),
                position_y: LittleEndian::read_i16(&buffer[14..16]),
            },
            closest_point: Point2D {
                position_x: LittleEndian::read_i16(&buffer[16..18]),
                position_y: LittleEndian::read_i16(&buffer[18..20]),
            },
            bounding_box_center: Point2D {
                position_x: LittleEndian::read_i16(&buffer[20..22]),
                position_y: LittleEndian::read_i16(&buffer[22..24]),
            },
            bounding_box_size: Size2D {
                size_x: LittleEndian::read_u16(&buffer[24..26]),
                size_y: LittleEndian::read_u16(&buffer[26..28]),
            },
            object_box_center: Point2D {
                position_x: LittleEndian::read_i16(&buffer[28..30]),
                position_y: LittleEndian::read_i16(&buffer[30..32]),
            },
            object_box_size: Size2D {
                size_x: LittleEndian::read_u16(&buffer[32..34]),
                size_y: LittleEndian::read_u16(&buffer[34..36]),
            },
            object_box_orientation: LittleEndian::read_i16(&buffer[36..38]),
            absolute_velocity: Point2D {
                position_x: LittleEndian::read_i16(&buffer[38..40]),
                position_y: LittleEndian::read_i16(&buffer[40..42]),
            },
            absolute_velocity_sigma: Size2D {
                size_x: LittleEndian::read_u16(&buffer[42..44]),
                size_y: LittleEndian::read_u16(&buffer[44..46]),
            },
            relative_velocity: Point2D {
                position_x: LittleEndian::read_i16(&buffer[46..48]),
                position_y: LittleEndian::read_i16(&buffer[48..50]),
            },
            reserved1: LittleEndian::read_u16(&buffer[50..52]),
            reserved2: LittleEndian::read_u16(&buffer[52..54]),
            reserved3: LittleEndian::read_u16(&buffer[54..56]),
            number_of_contour_points: LittleEndian::read_u16(&buffer[56..58]),
            contour_point_vec: Vec::new(),
        };
        for i in 0..(object_info.number_of_contour_points as usize) {
            object_info.contour_point_vec.push(
                Point2D {
                    position_x: LittleEndian::read_i16(&buffer[58+i*4..60+i*4]),
                    position_y: LittleEndian::read_i16(&buffer[60+i*4..62+i*4]),
                }
            );
        }
        object_info
    }

    fn print(&self) {
        println!("object_id: {}", self.object_id);
        println!("object_age: {}", self.object_age);
        println!("object_prediction_age: {}", self.object_prediction_age);
        println!("relative_timestamp: {}", self.relative_timestamp);
        print!("reference_point: ");
        self.reference_point.print();
        print!("reference_point_sigma: ");
        self.reference_point_sigma.print();
        print!("closest_point: ");
        self.closest_point.print();
        print!("bounding_box_center: ");
        self.bounding_box_center.print();
        print!("bounding_box_size: ");
        self.bounding_box_size.print();
        print!("object_box_center: ");
        self.object_box_center.print();
        print!("object_box_size: ");
        self.object_box_size.print();
        println!("object_box_orientation: {}", self.object_box_orientation);
        print!("absolute_velocity: ");
        self.absolute_velocity.print();
        print!("absolute_velosity_sigma: ");
        self.absolute_velocity_sigma.print();
        println!("number_of_contour_points: {}", self.number_of_contour_points);
        for i in 0..self.contour_point_vec.len() {
            self.contour_point_vec[i].print();
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Point2D {
    position_x: i16,
    position_y: i16,
}

impl Point2D {
    fn print(&self) {
        println!("{}, {}", self.position_x, self.position_y);
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Size2D {
    size_x: u16,
    size_y: u16,
}

impl Size2D {
    fn print(&self) {
        println!("{}, {}", self.size_x, self.size_y);
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct NtpTime {
    secs: u32,
    precise: u32,
}

impl NtpTime {
    fn datetime(&self) -> DateTime<Utc> {
        let standard_time: DateTime<Utc> = Utc.ymd(1900, 1, 1).and_hms(0, 0, 0);
        let duration_secs: Duration = Duration::seconds(self.secs as i64);
        let precise = self.precise * (pow::pow(10, 9) / pow::pow(2, 32));
        let duration_precise: Duration = Duration::nanoseconds(precise as i64);
        let duration = duration_secs + duration_precise;
        let utc: DateTime<Utc> = standard_time + duration;
        utc
    }

    fn print(&self) {
        println!("{}, {}", self.secs, self.precise);
    }

    fn print_datetime(&self) {
        let standard_time: DateTime<Utc> = Utc.ymd(1900, 1, 1).and_hms(0, 0, 0);
        let duration_secs: Duration = Duration::seconds(self.secs as i64);
        let precise = ((self.precise as f64) * (4294967296.0 / 1000000000.0)).round() as u32;
        let duration_precise: Duration = Duration::nanoseconds(precise as i64);
        let duration = duration_secs + duration_precise;
        let utc: DateTime<Utc> = standard_time + duration;
        println!("{:?}", utc);
    }
}

fn receive_payload(stream: &mut std::net::TcpStream, payload_len: u32) -> Vec<u8> {
    let mut remaining_len: u32 = payload_len;
    let mut buffer: [u8; 1024] = [0; 1024];
    let mut payload: Vec<u8> = Vec::new();
    while remaining_len > 0 {
        let mut msg_len = stream.read(&mut buffer[..]).unwrap();
        msg_len = if msg_len > (remaining_len as usize) {remaining_len as usize} else {msg_len};
        remaining_len = remaining_len - (msg_len as u32);
        payload.append(&mut buffer[0..msg_len].to_vec());
    }
    payload
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn ntp_time_now() -> u64 {
    let utc: DateTime<Utc> = Utc::now();
    let standard_time: DateTime<Utc> = Utc.ymd(1900, 1, 1).and_hms(0, 0, 0);
    let diff = utc.signed_duration_since(standard_time);
    let mut buffer: [u8; 8] = [0; 8];
    print!("{:?}", pow::pow(2, 32));
    let precise = ((diff.num_nanoseconds().unwrap() as f64) * (4294967296.0 / 1000000000.0)).round() as u32;
    BigEndian::write_u32(&mut buffer[0..4], diff.num_seconds() as u32);
    BigEndian::write_u32(&mut buffer[4..8], precise as u32);
    BigEndian::read_u64(&buffer)
}

fn sync_time(stream: &mut TcpStream) {
    let mut buffer: [u8; 34] = [0; 34];

    let header: Header = Header {
        magic_word: 0xaffec0c2,
        size_of_previous_messages: 0,
        size_of_message_data: 10,
        reserved: 0,
        device_id: 1,
        data_type: DataType::Command,
        ntp_time: NtpTime {
            secs: 0,
            precise: 0,
        },
    };
    header.encode(&mut buffer[0..24]);

    let now: u64 = ntp_time_now();
    let mut time: [u8; 8] = [0; 8];
    BigEndian::write_u64(&mut time, now);
    let sec: u32 = BigEndian::read_u32(&time[0..4]);
    let precise:u32 = BigEndian::read_u32(&time[4..8]);

    LittleEndian::write_u32(&mut buffer[24..28], 0x0030);
    LittleEndian::write_u16(&mut buffer[28..30], 0);
    LittleEndian::write_u32(&mut buffer[30..34], sec);
    stream.write(&buffer);

    LittleEndian::write_u32(&mut buffer[24..28], 0x0031);
    LittleEndian::write_u16(&mut buffer[28..30], 0);
    LittleEndian::write_u32(&mut buffer[30..34], precise);
    stream.write(&buffer);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("o", "", "set output file name", "NAME");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    let output = matches.opt_str("o").unwrap();

    let mut stream = TcpStream::connect("192.168.0.1:12002").unwrap();
    sync_time(&mut stream);
    let mut buffer: [u8; 24] = [0; 24];
    let mut file = BufWriter::new(File::create(output).unwrap());
    loop {
        let msg_len = stream.read(&mut buffer[..]).unwrap();
        if msg_len == 24 {
            let header = Header::new(buffer);
            if header.magic_word == 0xaffec0c2 {
                let mut payload: Vec<u8> = receive_payload(&mut stream, header.size_of_message_data);
                // println!("payload ");
                // for i in 0..(h.size_of_message_data as usize) {
                //     print!("{:02x}", payload[i]);
                // }
                // println!("");
                match header.data_type {
                    DataType::Command => {
                        // header.print();
                    },
                    DataType::CommandReply => {
                        // header.print();
                    },
                    DataType::Error => {
                        // header.print();
                    },
                    DataType::ScanData => {
                        // header.print();
                        // let scan_data = ScanData::new(payload.as_slice());
                    },
                    DataType::ObjectData => {
                        header.print();
                        let object_data = ObjectData::new(payload.as_slice());
                        // object_data.print();
                        let s_object_data = serde_yaml::to_string(&object_data).unwrap();
                        file.write(s_object_data.as_bytes()).unwrap();
                        file.write(b"\n").unwrap();
                    },
                    DataType::MovementData => {},
                    DataType::EgoMotionData => {},
                    DataType::SensorInfo => {},
                }
            }
        }
    }
}