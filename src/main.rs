use anyhow::{anyhow, Context, Result};
use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::combinator::{iterator, map, value};
use nom::multi::length_data;
use nom::number::complete::*;
use nom::sequence::{preceded, terminated, tuple};
use nom::IResult;
use ogg::writing::*;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

// --- Structures de Parsing ---

#[derive(Debug)]
pub struct Header {
    pub channel_count: u8,
    pub skip: u16,
    pub sample_rate: u32,
    pub data_offset: u32,
}

#[derive(Debug)]
pub struct OpusPacket {
    pub config: u8,
    pub stereo: bool,
    pub frames: u8,
}

// --- Constantes ---
pub const COMMENT_HEADER: &[u8] = b"OpusTags\x07\x00\x00\x00nx-opus\x00\x00\x00\x00";

// --- Fonctions de Parsing (Nom) ---
pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        tuple((
            tag(0x80000001u32.to_le_bytes()), // 0x00: magic
            take(5usize),                   // 0x04: skip 5 bytes
            le_u8,                          // 0x09: channel count
            take(2usize),                   // 0x0a: skip 2 bytes
            le_u32,                         // 0x0c: sample rate
            le_u32,                         // 0x10: data offset
            take(8usize),                   // 0x14: skip 8 bytes
            le_u16,                         // 0x1c: skip
        )),
        |(_, _, channel_count, _, sample_rate, data_offset, _, skip)| Header {
            channel_count,
            skip,
            sample_rate,
            data_offset,
        },
    )(input)
}

pub fn data_header(input: &[u8]) -> IResult<&[u8], u32> {
    preceded(tag(0x80000004u32.to_le_bytes()), le_u32)(input)
}

pub fn packet(input: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(terminated(be_u32, take(4usize)))(input)
}

pub fn opus_packet(input: &[u8]) -> IResult<&[u8], OpusPacket> {
    use nom::bits::{bits, complete::*};

    bits(map::<_, _, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((
            // CORRIGÉ: Spécifie le type de retour comme u8 pour les 5 bits de config
            take::<_, u8, _, _>(5usize), // config: u8
            map(take(1usize), |x: u8| x != 0), // stereo: bool
            alt((
                // CORRIGÉ: Forcer les valeurs littérales à être u8
                value(1u8, tag(0usize, 2usize)),
                value(2u8, tag(1usize, 2usize)),
                value(2u8, tag(2usize, 2usize)),
                preceded(
                    tag(3usize, 2usize),
                    preceded(
                        take::<_, u8, _, _>(2usize),
                        take(6usize), // frames: u8
                    ),
                ),
            )),
        )),
        // Les types (u8, bool, u8) sont maintenant déductibles
        |(config, stereo, frames)| OpusPacket {
            config, // config est déjà un u8
            stereo,
            frames: frames as u8,
        },
    ))(input)
}

// --- Fonctions Utilitaires ---

pub fn write_id_header(writer: &mut impl Write, header: &Header) -> Result<()> {
    writer.write_all(b"OpusHead")?;                         // magic
    writer.write_all(&[0x01])?;                             // version 1
    writer.write_all(&[header.channel_count])?;             // channels
    writer.write_all(&header.skip.to_le_bytes())?;          // pre-skip
    writer.write_all(&header.sample_rate.to_le_bytes())?;   // sample rate
    writer.write_all(&[0x00, 0x00])?;                       // gain (0)
    writer.write_all(&[0x00])?;                             // mapping family 0

    Ok(())
}

pub fn frame_size(config: u8) -> u64 {
    // Taille du frame en unités de 10ms (centaines de µs)
    const SILK: &[u64] = &[100, 200, 400, 600]; // 10ms, 20ms, 40ms, 60ms
    const HYBRID: &[u64] = &[100, 200]; // 10ms, 20ms
    const CELT: &[u64] = &[25, 50, 100, 200]; // 2.5ms, 5ms, 10ms, 20ms

    let sizes = match config {
        0..=11 => SILK,
        12..=15 => HYBRID,
        16..=31 => CELT,
        _ => unreachable!("Invalid Opus config encountered"),
    };

    let idx = config as usize % sizes.len();

    sizes[idx]
}

// --- Fonctions de Conversion ---

/// Convertit un seul fichier NX-Opus en Ogg Opus.
pub fn convert_file(input_path: &Path, output_path: &Path) -> Result<()> {
    println!("  -> Reading: {:?}", input_path);
    let file_data = fs::read(input_path)
        .context(format!("Failed to read input file: {:?}", input_path))?;
    let out_file = File::create(output_path)
        .context(format!("Failed to create output file: {:?}", output_path))?;
    let mut writer = PacketWriter::new(out_file);

    // 1. Parsing du Header
    let header = header(&file_data)
        .map_err(|e| anyhow!("Header parsing failed: {}", e))?.1;
    
    // 2. Écriture du OpusHead (Identification)
    let mut id_header: Vec<u8> = vec![];
    write_id_header(&mut id_header, &header)?;
    writer.write_packet(id_header.into(), 0, PacketWriteEndInfo::EndPage, 0)?;

    // 3. Écriture du OpusTags (Commentaires)
    writer.write_packet(COMMENT_HEADER.into(), 0, PacketWriteEndInfo::EndPage, 0)?;

    // 4. Préparation des paquets de données
    let (data, _length) =
        data_header(&file_data[header.data_offset as usize..])
            .map_err(|e| anyhow!("Data header parsing failed: {}", e))?;

    let mut iter = iterator(data, packet);
    let mut peekable = iter.into_iter().enumerate().peekable();
    let mut pos = 0; // Granule position (samples)

    // 5. Boucle de conversion des paquets
    while let Some((i, packet)) = peekable.next() {
        let opus = opus_packet(packet)
            .map_err(|e| anyhow!("Opus packet header parsing failed: {}", e))?.1;
            
        // Calcul de la durée en samples
        let size_ms = frame_size(opus.config);
        let duration = 48000 * size_ms / 1000;

        pos += duration;

        let end = if peekable.peek().is_none() {
            PacketWriteEndInfo::EndStream
        } else if (i + 1) % (header.channel_count as usize) == 0 {
            PacketWriteEndInfo::EndPage
        } else {
            PacketWriteEndInfo::NormalPacket
        };
        
        // Écriture du paquet de données
        writer.write_packet(packet.into(), 0, end, pos)?;
    }

    iter.finish().map_err(|e| anyhow!("Iterator finish failed: {}", e))?;
    Ok(())
}

/// Convertit tous les fichiers dans un dossier.
pub fn convert_folder(input_folder_path: &Path, output_folder_path: &Path) -> Result<()> {
    println!("  -> Creating output directory: {:?}", output_folder_path);
    fs::create_dir_all(output_folder_path)
        .context(format!("Failed to create output directory: {:?}", output_folder_path))?;

    println!("\n--- Starting Folder Conversion ---");

    for entry in fs::read_dir(input_folder_path)? {
        let entry = entry?;
        let input_path = entry.path();

        if input_path.is_file() {
            let file_name = input_path.file_stem()
                .ok_or_else(|| anyhow!("Invalid file name: {:?}", input_path))?;
            
            let mut output_file_name: PathBuf = file_name.into();
            output_file_name.set_extension("opus");
            
            let output_path = output_folder_path.join(output_file_name);

            match convert_file(&input_path, &output_path) {
                Ok(_) => println!("  ✅ Success: {:?}", output_path),
                Err(e) => eprintln!("  ❌ Failed to convert {:?}: {}", input_path, e),
            }
        }
    }
    
    println!("--- Folder Conversion Complete ---\n");
    Ok(())
}

/// Fonction utilitaire pour lire l'entrée utilisateur
fn read_input(prompt: &str) -> Result<String> {
    print!("{} ", prompt);
    std::io::stdout().flush()?; 
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// --- Fonction Principale ---

fn main() -> Result<()>
{
    println!("--- NX-opus to Ogg Opus converter - 2025 ---");
    println!("authors : leo60228 & geo6453");
    
    let choice = read_input("Do you want to convert one file or a whole folder ? (file/folder)")?;

    if choice.eq_ignore_ascii_case("file")
    {
        println!("\nMode selected: Convert a single file");
        
        let input_path_str = read_input("Enter input file path (e.g. : input.opus):")?;
        let output_path_str = read_input("Enter output file path (e.g. : output.opus):")?;
        
        convert_file(
             Path::new(&input_path_str),
             Path::new(&output_path_str),
        )?;
        println!("\nConversion completed successfully for a single file.");

    } else if choice.eq_ignore_ascii_case("folder") {
        println!("\nMode selected: Convert a whole folder");
        
        let input_folder_path_str = read_input("Enter input folder path:")?;
        let output_folder_path_str = read_input("Enter output folder path:")?;

        convert_folder(
            Path::new(&input_folder_path_str), 
            Path::new(&output_folder_path_str)
        )?;
        println!("\nFolder conversion process finished.");

    } else {
        eprintln!("\n❌ Invalid choice! Please type 'file' or 'folder'.");
    }

    Ok(())
}