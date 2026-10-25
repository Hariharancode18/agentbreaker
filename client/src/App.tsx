import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { Route, Switch } from "wouter";
import Home from "./pages/Home";
import NotFound from "./pages/NotFound";

function Router() {
  return <Switch>
    <Route path="/" component={Home} />
    <Route path="/agents" component={Home} />
    <Route path="/attack-lab" component={Home} />
    <Route path="/executions" component={Home} />
    <Route path="/execution/:executionId" component={Home} />
    <Route path="/vulnerabilities" component={Home} />
    <Route path="/reports" component={Home} />
    <Route path="/documentation" component={Home} />
    <Route component={NotFound} />
  </Switch>;
}

export default function App() {
  return <ErrorBoundary>
    <ThemeProvider defaultTheme="dark">
      <TooltipProvider>
        <Toaster theme="dark" />
        <Router />
      </TooltipProvider>
    </ThemeProvider>
  </ErrorBoundary>;
}
