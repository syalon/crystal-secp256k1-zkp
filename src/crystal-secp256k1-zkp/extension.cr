
struct Slice(T)

  def +(others : Bytes) : Bytes
    io = IO::Memory.new
    io.write(self)
    io.write(others)
    return io.to_slice
  end

end
