//// Placeholder for any interactive functionality needed on the home page
//// Example: Handling menu interactions or dynamic content loading
//
//document.addEventListener('DOMContentLoaded', () => {
//    // Example: Initialize any dynamic components or handle menu interactions here
//
//    // Example function to handle menu toggle if needed
//    const menuToggle = document.querySelector('.menu-toggle');
//    const navLinks = document.querySelector('.nav-links');
//
//    if (menuToggle && navLinks) {
//      menuToggle.addEventListener('click', () => {
//        navLinks.classList.toggle('active');
//      });
//    }
//  });
//
//  // Add this to your index_script.js
//  document.addEventListener('DOMContentLoaded', () => {
//    const videoItems = document.querySelectorAll('.video-item');
//    const miniPlayer = document.getElementById('mini-player');
//    const videoPlayer = document.getElementById('video-player');
//    const videoSource = document.getElementById('video-source');
//
//    videoItems.forEach(item => {
//        item.addEventListener('click', (event) => {
//            event.preventDefault();
//            const videoId = item.getAttribute('data-video-id');  // Assuming each item has a data attribute for video ID
//            const streamUrl = `/stream/${videoId}`;
//            videoSource.src = streamUrl;
//            videoPlayer.load();
//            miniPlayer.classList.remove('hidden');
//        });
//    });
//
//    // Optionally, you can add a click event to the mini player to close it
//    miniPlayer.addEventListener('click', () => {
//        miniPlayer.classList.add('hidden');
//        videoPlayer.pause();
//    });
//});
//
