#!/bin/bash
# Quick fix: Create disk_forensics.json playbook on Linux

cat > ~/ctf-ai-ultimate/playbooks/disk_forensics.json << 'EOF'
{
    "name": "disk_forensics",
    "description": "Comprehensive disk image forensics analysis (.dd, .img, .raw, .vmdk)",
    "file_types": [
        "DOS/MBR boot sector",
        "x86 boot sector",
        "disk image",
        "filesystem",
        "FAT",
        "NTFS",
        "ext2",
        "ext3",
        "ext4"
    ],
    "steps": [
        {
            "name": "File Type Detection",
            "description": "Identify disk image type and filesystem",
            "command": "file {target}",
            "parse_output": true
        },
        {
            "name": "Strings Analysis (Quick Win)",
            "description": "Extract all strings and search for flags",
            "command": "strings {target} | grep -iE '(flag|picoCTF|CTF\\{|flag\\{)'",
            "parse_output": true,
            "continue_on_error": true
        },
        {
            "name": "Comprehensive Strings Extraction",
            "description": "Extract all printable strings to file",
            "command": "strings {target} > {output_dir}/strings.txt",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Partition Table Analysis",
            "description": "Check partition structure with fdisk",
            "command": "fdisk -l {target}",
            "parse_output": true,
            "continue_on_error": true
        },
        {
            "name": "Partition Analysis (mmls)",
            "description": "Analyze partitions with Sleuthkit mmls",
            "command": "mmls {target}",
            "parse_output": true,
            "continue_on_error": true
        },
        {
            "name": "File Listing (fls)",
            "description": "List all files in the filesystem",
            "command": "fls -r {target} > {output_dir}/file_list.txt",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Deleted Files Detection",
            "description": "Find deleted files with fls",
            "command": "fls -r -d {target} > {output_dir}/deleted_files.txt",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Mount Attempt (Read-Only)",
            "description": "Try to mount the disk image",
            "command": "mkdir -p {output_dir}/mnt && sudo mount -o loop,ro {target} {output_dir}/mnt",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Search Mounted Files",
            "description": "Search for flags in mounted filesystem",
            "command": "grep -r -iE '(flag|picoCTF|CTF\\{)' {output_dir}/mnt/ 2>/dev/null",
            "parse_output": true,
            "continue_on_error": true
        },
        {
            "name": "List Mounted Contents",
            "description": "List all files in mounted filesystem",
            "command": "find {output_dir}/mnt/ -type f 2>/dev/null > {output_dir}/mounted_files.txt",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Hexdump Analysis",
            "description": "Check first 512 bytes (boot sector)",
            "command": "xxd -l 512 {target} > {output_dir}/boot_sector.hex",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Binwalk Scan",
            "description": "Scan for embedded files and signatures",
            "command": "binwalk {target}",
            "parse_output": true,
            "continue_on_error": true
        },
        {
            "name": "Foremost Carving",
            "description": "Carve files from disk image",
            "command": "foremost -i {target} -o {output_dir}/carved",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Scalpel Carving",
            "description": "Advanced file carving with scalpel",
            "command": "scalpel {target} -o {output_dir}/scalpel_output",
            "parse_output": false,
            "continue_on_error": true
        },
        {
            "name": "Search Carved Files",
            "description": "Search for flags in carved files",
            "command": "grep -r -iE '(flag|picoCTF|CTF\\{)' {output_dir}/carved/ 2>/dev/null",
            "parse_output": true,
            "continue_on_error": true
        },
        {
            "name": "Unmount Cleanup",
            "description": "Unmount the disk image if mounted",
            "command": "sudo umount {output_dir}/mnt 2>/dev/null || true",
            "parse_output": false,
            "continue_on_error": true
        }
    ],
    "flag_patterns": [
        "picoCTF\\{[^}]+\\}",
        "flag\\{[^}]+\\}",
        "FLAG\\{[^}]+\\}",
        "CTF\\{[^}]+\\}"
    ],
    "recommended_tools": [
        "strings",
        "file",
        "fdisk",
        "mmls",
        "fls",
        "icat",
        "mount",
        "binwalk",
        "foremost",
        "scalpel",
        "autopsy",
        "xxd"
    ],
    "notes": [
        "Disk images often contain flags in plain text within files",
        "Check deleted files - they may contain the flag",
        "FAT32 filesystems are common in CTF challenges",
        "Always try 'strings' first for quick wins",
        "Mount the image to browse files normally",
        "Use file carving if files are deleted or corrupted"
    ]
}
EOF

echo "✅ Created disk_forensics.json playbook!"
echo "Now run: sudo ctf-ai --solve /home/siva/Downloads/disko-1.dd.gz"
EOF

chmod +x ~/ctf-ai-ultimate/playbooks/disk_forensics.json
