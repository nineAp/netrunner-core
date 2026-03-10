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
      <div className="fixed inset-0 h-screen w-full overflow-hidden bg-background">
        <AnimatedBackground />

        <div className="bg-background">
          <Header onMenuClick={() => setIsMenuOpen(!isMenuOpen)} />
        </div>

        <BurgerMenu isOpen={isMenuOpen} onClose={() => setIsMenuOpen(false)} />
        <main className="flex h-[calc(100vh-4rem)] flex-col items-center justify-center px-6 py-6 overflow-hidden">
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
