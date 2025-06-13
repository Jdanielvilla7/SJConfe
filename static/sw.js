self.addEventListener("install", event => {
  console.log("Service Worker instalado");
});

self.addEventListener("fetch", event => {
  // Puedes personalizar la lógica de caché aquí si deseas
});
