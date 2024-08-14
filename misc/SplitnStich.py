import os
from moviepy.editor import VideoFileClip, concatenate_videoclips

def split_file(file_path, chunk_size_mb=1):
    chunk_size = chunk_size_mb * 1024 * 1024  # Convert MB to bytes
    file_name = os.path.basename(file_path)
    folder_name = os.path.splitext(file_name)[0]

    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    try:
        clip = VideoFileClip(file_path)
        total_duration = clip.duration
        chunk_number = 1
        start_time = 0

        while start_time < total_duration:
            end_time = min(start_time + (chunk_size / (clip.fps * clip.size[0] * clip.size[1])), total_duration)
            chunk = clip.subclip(start_time, end_time)
            chunk_file_name = f"{file_name}_part_{chunk_number}.mp4"
            chunk_file_path = os.path.join(folder_name, chunk_file_name)
            chunk.write_videofile(chunk_file_path, codec="libx264", audio_codec="aac")
            start_time = end_time
            chunk_number += 1

        print(f"File split into {chunk_number - 1} chunks and saved in folder '{folder_name}'")

    except PermissionError:
        print(f"Permission denied: Could not read '{file_path}' or write to '{folder_name}'")
    except FileNotFoundError:
        print(f"File not found: '{file_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")

def stitch_file(folder_name, output_file_path):
    try:
        video_clips = []
        files = sorted([f for f in os.listdir(folder_name) if f.endswith('.mp4')],
                       key=lambda x: int(x.split('_part_')[-1].split('.mp4')[0]))

        for file_name in files:
            file_path = os.path.join(folder_name, file_name)
            clip = VideoFileClip(file_path)
            video_clips.append(clip)

        final_clip = concatenate_videoclips(video_clips)
        final_clip.write_videofile(output_file_path, codec="libx264", audio_codec="aac")

        print(f"Files in folder '{folder_name}' have been stitched into '{output_file_path}'")

    except PermissionError:
        print(f"Permission denied: Could not write to '{output_file_path}'")
    except FileNotFoundError:
        print(f"Folder '{folder_name}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    mode = input("Enter 'split' to split a file or 'stitch' to stitch files: ").strip().lower()

    if mode == 'split':
        file_path = input("Enter the path of the .mp4 file to be split: ").strip()
        split_file(file_path)
    elif mode == 'stitch':
        folder_name = input("Enter the name of the folder containing the chunks: ").strip()
        output_file_path = input("Enter the path for the stitched .mp4 file: ").strip()
        stitch_file(folder_name, output_file_path)
    else:
        print("Invalid mode. Please enter either 'split' or 'stitch'.")

if __name__ == "__main__":
    main()
