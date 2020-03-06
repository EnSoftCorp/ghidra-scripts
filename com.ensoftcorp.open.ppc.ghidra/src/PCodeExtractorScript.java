import java.util.ArrayList;
import java.util.Iterator;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.Writer;
import java.io.IOException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.Transformer;
import javax.xml.transform.*;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import java.io.File;
import java.util.Set;
import java.util.Base64;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.VarnodeTranslator;

public class PCodeExtractorScript extends GhidraScript {

	private String genAddr(Address addr) {
		String ret = "0x";
		ret += addr.toString();
		return ret;
	}

	private ArrayList<Element> generateInstTag(Instruction ir, Document doc, VarnodeTranslator trans,
			AddressSetView addressRange) throws Exception {

		ArrayList<Element> instrTags = new ArrayList<Element>();
		while (ir != null && (addressRange.contains(ir.getAddress()))) {
			String readRegisters = " ";
			String writtenRegisters = " ";
			String constants = " ";
			PcodeOp[] pcode = ir.getPcode();
			for (int i = 0; i < pcode.length; i++) {
				Varnode[] varnodes_in = pcode[i].getInputs();
				for (int j = 0; j < varnodes_in.length; j++) {
					Varnode vr = varnodes_in[j];

					if (vr.isRegister()) {
						Register reg = trans.getRegister(vr);
						if (reg != null) {
							readRegisters += reg.getName() + ",";
						}
					} else if (vr.isConstant()) {
						constants += "0x" + Long.toHexString(vr.getOffset()) + ":" + String.valueOf(vr.getSize()) + ",";
					}
				}

				Varnode varnode_out = pcode[i].getOutput();
				if (varnode_out != null) {
					if (varnode_out.isRegister()) {
						Register reg = trans.getRegister(varnode_out);
						if (reg != null) {
							writtenRegisters += reg.getName() + ",";
						}
					}
				}
			}
			if (readRegisters.length() > 0 && readRegisters.charAt(readRegisters.length() - 1) == ',')
				readRegisters = readRegisters.substring(0, readRegisters.length() - 1);
			if (writtenRegisters.length() > 0 && writtenRegisters.charAt(writtenRegisters.length() - 1) == ',')
				writtenRegisters = writtenRegisters.substring(0, writtenRegisters.length() - 1);
			if (constants.length() > 0 && constants.charAt(constants.length() - 1) == ',')
				constants = constants.substring(0, constants.length() - 1);
			String disas = ir.toString();

			Element instrTag = doc.createElement("Instruction");
			Attr asmA = doc.createAttribute("asm");
			asmA.setValue(disas);
			instrTag.setAttributeNode(asmA);
			Attr asmAddr = doc.createAttribute("addr");
			asmAddr.setValue("0x" + Long.toHexString(ir.getAddress().getOffset()));
			instrTag.setAttributeNode(asmAddr);
			Attr binVal = doc.createAttribute("opcodes");
			Base64.Encoder encoder = Base64.getEncoder();
			byte irb[] = ir.getBytes();
			binVal.setValue(encoder.encodeToString(irb));
			instrTag.setAttributeNode(binVal);
			Attr writeRegA = doc.createAttribute("writeRegisters");
			writeRegA.setValue(writtenRegisters);
			instrTag.setAttributeNode(writeRegA);
			Attr readRegA = doc.createAttribute("readRegisters");
			readRegA.setValue(readRegisters);
			instrTag.setAttributeNode(readRegA);
			Attr constantsA = doc.createAttribute("constants");
			constantsA.setValue(constants);
			instrTag.setAttributeNode(constantsA);
			Attr operationA = doc.createAttribute("operation");
			operationA.setValue(ir.getMnemonicString());
			instrTag.setAttributeNode(operationA);

			Attr flowsA = doc.createAttribute("flows");
			String flowStr = " ";
			for (Address a : ir.getFlows()) {
				if (flowStr.length() > 1) {
					flowStr += ",";
				}
				flowStr += a.toString();
			}
			flowsA.setValue(flowStr);
			instrTag.setAttributeNode(flowsA);
			instrTags.add(instrTag);
			ir = getInstructionAfter(ir);
		}
		return instrTags;
	}

	private String fixFunctionName(String funcName) {
		return funcName.replaceAll("/", "_");
	}

	private String symTypeToStr(SymbolType symType) {
		String symTypeStr = "";
		if (symType.equals(SymbolType.CLASS)) {
			symTypeStr = "class";
		} else if (symType.equals(SymbolType.CODE)) {
			symTypeStr = "code";
		} else if (symType.equals(SymbolType.FUNCTION)) {
			symTypeStr = "function";
		} else if (symType.equals(SymbolType.GLOBAL)) {
			symTypeStr = "global";
		} else if (symType.equals(SymbolType.GLOBAL_VAR)) {
			symTypeStr = "global_var";
		} else if (symType.equals(SymbolType.LIBRARY)) {
			symTypeStr = "library";
		} else if (symType.equals(SymbolType.LOCAL_VAR)) {
			symTypeStr = "local_var";
		} else if (symType.equals(SymbolType.PARAMETER)) {
			symTypeStr = "parameter";
		} else if (symType.equals(SymbolType.NAMESPACE)) {
			symTypeStr = "namespace";
		} else {
			symTypeStr = "unknown";
		}
		return symTypeStr;
	}

	private String symSrcToStr(SourceType symSrc) {
		String symSrcStr = "";
		switch (symSrc) {
			case IMPORTED:
				symSrcStr = "imported";
				break;
			case DEFAULT:
				symSrcStr = "default";
				break;
			case USER_DEFINED:
				symSrcStr = "user_defined";
				break;
			case ANALYSIS:
				symSrcStr = "analysis";
				break;
		}
		return symSrcStr;
	}

	@Override
	public void run() throws Exception {
		// Get script arguments
		String[] args = getScriptArgs();
		String tmpFilePrefix = args[0];

		DecompInterface decompInterface = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		decompInterface.toggleCCode(true);
		decompInterface.setSimplificationStyle("decompile");
		decompInterface.openProgram(currentProgram);
		VarnodeTranslator trans = new VarnodeTranslator(currentProgram);
		FunctionManager funcMan = currentProgram.getFunctionManager();
		FunctionIterator funcIter = funcMan.getFunctions(true);
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.newDocument();
		Element binaryTag = doc.createElement("Binary");
		doc.appendChild(binaryTag);

		SymbolTable symTab = currentProgram.getSymbolTable();
		SymbolIterator symIt = symTab.getAllSymbols(true);
		for (Symbol sym : symIt) {
			String symSrcStr = symSrcToStr(sym.getSource());
			String symTypeStr = symTypeToStr(sym.getSymbolType());

			if (symTypeStr.length() > 0 && !sym.getAddress().toString().contains("EXTERNAL")
					&& !sym.getAddress().toString().contains(".") && !sym.getAddress().toString().contains(":")) {
				Element symTag = doc.createElement("symbol");
				Attr symName = doc.createAttribute("name");
				symName.setValue(fixFunctionName(sym.getName()));
				symTag.setAttributeNode(symName);
				Attr symSrcA = doc.createAttribute("source");
				symSrcA.setValue(symSrcStr);
				symTag.setAttributeNode(symSrcA);
				Attr symAddrA = doc.createAttribute("address");
				symAddrA.setValue("0x" + sym.getAddress().toString());
				symTag.setAttributeNode(symAddrA);
				Attr symTypeA = doc.createAttribute("type");
				symTypeA.setValue(symTypeStr);
				symTag.setAttributeNode(symTypeA);
				binaryTag.appendChild(symTag);
			}
		}

		while (funcIter.hasNext() && !monitor.isCancelled()) {
			Function func = funcIter.next();
			if (func == null) {
				println("[ERROR] decompiling function " + func.getName());
				break;
			}
			DecompileResults res = decompInterface.decompileFunction(func, 30, null);
			if (res == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}
			HighFunction hf = res.getHighFunction();
			if (hf == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}
			ArrayList<PcodeBlockBasic> bbs = hf.getBasicBlocks();
			if (bbs == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}
			AddressSetView addressRange = func.getBody();
			if (addressRange == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}
			Instruction ir = getFirstInstruction(func);
			if (ir == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}
			Set<Function> calledFuncs = func.getCalledFunctions(monitor);
			Set<Function> calledFromFuncs = func.getCallingFunctions(monitor);
			if (calledFuncs == null || calledFromFuncs == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}
			String calledFuncsStr = " ";
			String callingFuncsStr = " ";
			for (Function f : calledFuncs) {
				calledFuncsStr += fixFunctionName(f.getName()) + ",";
			}
			for (Function f : calledFromFuncs) {
				callingFuncsStr += fixFunctionName(f.getName()) + ",";
			}

			Element funcTag = doc.createElement("Function");
			binaryTag.appendChild(funcTag);
			Attr fname = doc.createAttribute("name");
			fname.setValue(fixFunctionName(func.getName()));
			funcTag.setAttributeNode(fname);
			Attr calledFuncsA = doc.createAttribute("calledFuncs");
			calledFuncsA.setValue(calledFuncsStr);
			funcTag.setAttributeNode(calledFuncsA);
			Attr callingFuncsA = doc.createAttribute("callingFuncs");
			callingFuncsA.setValue(callingFuncsStr);
			funcTag.setAttributeNode(callingFuncsA);
			Attr callingA = doc.createAttribute("return_type");
			callingA.setValue(func.getReturnType().getName());
			funcTag.setAttributeNode(callingA);
			Attr startA = doc.createAttribute("start");
			startA.setValue(genAddr(addressRange.getMinAddress()));
			funcTag.setAttributeNode(startA);
			Attr endA = doc.createAttribute("end");
			endA.setValue(genAddr(addressRange.getMaxAddress()));
			funcTag.setAttributeNode(endA);

			String thunk = "not-thunk";
			String thunkFuncRef = "";
			Function thunkFuncRefFunc = null;
			if (func.isThunk()) {
				thunk = "thunk";
				thunkFuncRefFunc = func.getThunkedFunction(false);
				thunkFuncRef = fixFunctionName(thunkFuncRefFunc.getName());
			}
			Attr thunkA = doc.createAttribute("thunk");
			thunkA.setValue(thunk);
			funcTag.setAttributeNode(thunkA);
			Attr thunkRA = doc.createAttribute("thunkRef");
			thunkRA.setValue(thunkFuncRef);
			funcTag.setAttributeNode(thunkRA);

			if (ir == null) {
				println("[ERROR] decompiling function " + func.getName());
				continue;
			}

			ArrayList<Element> instTags = generateInstTag(ir, doc, trans, addressRange);
			for (Element tag : instTags) {
				funcTag.appendChild(tag);
			}

			for (PcodeBlockBasic bb : bbs) {
				int inEdges = bb.getInSize();
				int outEdges = bb.getOutSize();

				Element bbXml = doc.createElement("BasicBlock");
				Attr bbXmlStart = doc.createAttribute("start");
				Attr bbXmlEnd = doc.createAttribute("end");
				Attr numInEdges = doc.createAttribute("in_edges");
				Attr numOutEdges = doc.createAttribute("out_edges");

				bbXmlStart.setValue("0x" + bb.getStart().toString());
				bbXmlEnd.setValue("0x" + bb.getStop().toString());
				numInEdges.setValue(Integer.toString(inEdges));
				numOutEdges.setValue(Integer.toString(outEdges));

				bbXml.setAttributeNode(bbXmlStart);
				bbXml.setAttributeNode(bbXmlEnd);
				bbXml.setAttributeNode(numInEdges);
				bbXml.setAttributeNode(numOutEdges);
				funcTag.appendChild(bbXml);

				for (int i = 0; i < inEdges; i++) {
					Element inEdge = doc.createElement("InEdge");
					PcodeBlock in = bb.getIn(i);
					Attr edgeAddr = doc.createAttribute("edge_addr");
					edgeAddr.setValue("0x" + in.getStart().toString());
					inEdge.setAttributeNode(edgeAddr);
					bbXml.appendChild(inEdge);
				}
				for (int i = 0; i < outEdges; i++) {
					Element outEdge = doc.createElement("OutEdge");
					PcodeBlock out = bb.getOut(i);
					Attr edgeAddr = doc.createAttribute("edge_addr");
					edgeAddr.setValue("0x" + out.getStart().toString());
					outEdge.setAttributeNode(edgeAddr);
					bbXml.appendChild(outEdge);
				}
			}
		}

		exportXML(doc, tmpFilePrefix);
	}

	private void exportXML(Document doc, String tmpFilePrefix) {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
		DOMSource source = new DOMSource(doc);
		File out = new File("/tmp/binary-" + tmpFilePrefix + ".xml");
		StreamResult result = new StreamResult(out);
		transformer.transform(source, result);
	}
}