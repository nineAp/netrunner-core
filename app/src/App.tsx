import { useState } from "react";
import { Header } from "./features/Header";
import { AnimatedBackground } from "./components/shared/AnimatedBackground";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { BurgerMenu } from "./features/BurgerMenu";
import { Home } from "./pages/Home";
import { About } from "./pages/About";
import { Settings } from "./pages/Settings";

function App() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <BrowserRouter>
      <div className="min-h-screen w-full bg-background relative overflow-x-hidden">
        <AnimatedBackground />
        <Header onMenuClick={() => setIsMenuOpen(!isMenuOpen)} />

        <BurgerMenu isOpen={isMenuOpen} onClose={() => setIsMenuOpen(false)} />

        <main className="flex flex-col items-center justify-center min-h-[calc(100vh-80px)] gap-[10px] p-6">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
