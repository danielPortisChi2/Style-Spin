const coin = document.getElementById('coin');
  let rotation = 0;
  let speed = 5; // Start slower rotation speed (degrees per frame)
  const totalSpins = 100000000000;
  const targetRotation = totalSpins * 360;
  let slowingDown = false;

  function animate() {
    if (!slowingDown) {
      rotation += speed;
      if (rotation >= targetRotation) {
        slowingDown = true;
      }
    } else {
      speed *= 0.95;  // slow down smoothly
      rotation += speed;

      if (speed < 0.4) {
        // Snap rotation to nearest 360 multiple for heads facing front
        rotation = Math.round(rotation / 360) * 360;
        coin.style.transform = `rotateY(${rotation}deg)`;
        return; // stop animation
      }
    }

    coin.style.transform = `rotateY(${rotation}deg)`;
    requestAnimationFrame(animate);
  }

  animate();

  // Optional: restart spin on click
  /*
  coin.parentElement.addEventListener('click', () => {
    if (!slowingDown) return;  // prevent restart mid-spin
    rotation = 0;
    speed = 5;
    slowingDown = false;
    animate();
  });
  */